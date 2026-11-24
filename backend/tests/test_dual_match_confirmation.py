"""双匹配核验、签认分类、争议隔离、规则修订和幂等入库测试。"""
from __future__ import annotations

import concurrent.futures
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import LogEntry, ParseRule
from app.core.pipeline import IngestPipeline


def _entry(raw: str, number: int, source: str = "SRC-1") -> LogEntry:
    return LogEntry(raw_line=raw, line_number=number, source_id=source)


def _conflict_pipeline(reverse: bool = False):
    pipeline = IngestPipeline()
    error_rule = ParseRule(
        "RULE-ERROR", "SRC-1", r"^(ERROR)\s+LOGIN$", ["level"],
        state="生效中", priority=10,
    )
    login_rule = ParseRule(
        "RULE-LOGIN", "SRC-1", r"^ERROR\s+(LOGIN)$", ["action"],
        state="生效中", priority=20,
    )
    same_one = ParseRule(
        "RULE-SAME-1", "SRC-1", r"^(OK)\s+OK$", ["level"],
        state="生效中", priority=10,
    )
    same_two = ParseRule(
        "RULE-SAME-2", "SRC-1", r"^OK\s+(OK)$", ["level"],
        state="生效中", priority=20,
    )
    rules = [error_rule, login_rule, same_one, same_two]
    if reverse:
        rules.reverse()
    entries = [_entry("ERROR LOGIN", 1), _entry("OK OK", 2), _entry("NO MATCH", 3)]
    pipeline.apply_parse_rules(entries, rules)
    pipeline.sign_rule(rule_id="RULE-ERROR", owner_group="错误监控组", responsibility="故障")
    pipeline.sign_rule(rule_id="RULE-LOGIN", owner_group="账号审计组", responsibility="登录")
    pipeline.sign_rule(rule_id="RULE-SAME-1", owner_group="平台组", responsibility="正常")
    pipeline.sign_rule(rule_id="RULE-SAME-2", owner_group="平台组", responsibility="正常")
    return pipeline, entries


def test_each_rule_fields_and_unmatched_reason_are_queryable():
    pipeline, entries = _conflict_pipeline()
    pipeline.classify_events(entries)
    assert pipeline.get_rule_fields("ERROR LOGIN", "RULE-ERROR") == {"level": "ERROR"}
    assert pipeline.get_rule_fields("ERROR LOGIN", "RULE-LOGIN") == {"action": "LOGIN"}
    reasons = pipeline.get_unmatched_reasons("NO MATCH")
    assert reasons and all("未匹配" in reason for reason in reasons)


def test_same_meaning_success_has_one_official_and_two_confirmations():
    pipeline, entries = _conflict_pipeline()
    records = pipeline.classify_events(entries)
    ok_records = [r for r in records if r.original_content == "OK OK"]
    assert len(ok_records) == 1
    assert ok_records[0].event_type.type_id == "EVEN-0001"
    confirmations = pipeline.dual_match_batch.get_confirmation_records("OK OK")
    assert {c.rule_id for c in confirmations} == {"RULE-SAME-1", "RULE-SAME-2"}
    assert len(pipeline.official_classifications) == 1


def test_contradictory_signed_decisions_are_isolated():
    pipeline, entries = _conflict_pipeline()
    records = pipeline.classify_events(entries)
    assert all(r.original_content != "ERROR LOGIN" for r in records)
    disputes = pipeline.get_disputes()
    assert len(disputes) == 1
    dispute = disputes[0]
    assert dispute.raw_line == "ERROR LOGIN"
    assert dispute.classification_keys == ["EVEN-0002", "EVEN-0003"]
    replayed = pipeline.rerun_dispute(dispute.dispute_id)
    assert replayed is not None
    assert replayed.classification_keys == ["EVEN-0002", "EVEN-0003"]


def test_rule_registration_order_does_not_change_classification():
    first, first_entries = _conflict_pipeline(reverse=False)
    first_records = first.classify_events(first_entries)
    first.store_events(first_records)

    second, second_entries = _conflict_pipeline(reverse=True)
    second_records = second.classify_events(second_entries)
    second.store_events(second_records)

    def summary(pipeline, records):
        return (
            [(r.original_content, r.event_type.type_id) for r in records],
            sorted(d.classification_keys for d in pipeline.get_disputes()),
            sum(len(rows) for rows in pipeline.get_event_store().values()),
        )

    assert summary(first, first_records) == summary(second, second_records)


def test_concurrent_same_official_classification_is_stored_once():
    pipeline, entries = _conflict_pipeline()
    start = threading.Barrier(8)

    def submit(_):
        start.wait()
        result = pipeline.submit_classification(entries)
        return result["stored_count"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        stored_counts = list(pool.map(submit, range(64)))

    assert sum(stored_counts) == 1
    assert sum(len(rows) for rows in pipeline.get_event_store().values()) == 1
    assert len(pipeline.official_classifications) == 1


def test_revised_rule_only_reruns_line_it_actually_hit():
    pipeline = IngestPipeline()
    revised_rule = ParseRule(
        "RULE-REVISED", "SRC-2", r"^REVISE\s+(ERROR)$", ["level"], state="生效中",
    )
    unaffected_rule = ParseRule(
        "RULE-OTHER", "SRC-2", r"^OTHER\s+(LOGIN)$", ["action"], state="生效中",
    )
    affected = _entry("REVISE ERROR", 1, "SRC-2")
    unaffected = _entry("OTHER LOGIN", 2, "SRC-2")
    pipeline.apply_parse_rules([affected, unaffected], [revised_rule, unaffected_rule])
    pipeline.sign_rule(rule_id="RULE-REVISED", owner_group="错误组", responsibility="故障")
    pipeline.sign_rule(rule_id="RULE-OTHER", owner_group="审计组", responsibility="登录")
    pipeline.classify_events([affected, unaffected])

    affected_official = pipeline.official_classifications[affected.line_key]
    unaffected_official = pipeline.official_classifications[unaffected.line_key]
    unaffected_record = unaffected_official.record
    assert affected_official.event_type_id == "EVEN-0002"
    assert unaffected_official.event_type_id == "EVEN-0003"

    result = pipeline.revise_rule(
        rule=revised_rule,
        regex_pattern=r"^REVISE\s+(ERROR)$",
        field_names=["action"],
    )
    assert result["rerun_line_keys"] == [affected.line_key]

    changed = pipeline.official_classifications[affected.line_key]
    untouched = pipeline.official_classifications[unaffected.line_key]
    assert changed.event_type_id == "EVEN-0001"
    assert changed.confirmed_version == 2
    assert untouched.event_type_id == "EVEN-0003"
    assert untouched.confirmed_version == 1
    assert untouched.record is unaffected_record
    historical_fields = [r.fields for r in pipeline.get_match_results("REVISE ERROR", "RULE-REVISED")]
    assert historical_fields == [{"level": "ERROR"}, {"action": "ERROR"}]


def test_withdrawn_rule_historical_fields_remain_queryable():
    pipeline = IngestPipeline()
    rule = ParseRule("RULE-WITHDRAWN", "SRC-3", r"^(ERROR)$", ["level"], state="生效中")
    entry = _entry("ERROR", 1, "SRC-3")
    pipeline.apply_parse_rules([entry], [rule])
    pipeline.sign_rule(rule_id="RULE-WITHDRAWN", responsibility="故障")
    pipeline.classify_events([entry])
    assert pipeline.official_classifications[entry.line_key].event_type_id == "EVEN-0002"

    rule.state = "已撤下"
    pipeline.retry_classification()
    assert pipeline.get_rule_fields("ERROR", "RULE-WITHDRAWN") == {"level": "ERROR"}


if __name__ == "__main__":
    import traceback

    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  PASS  {test.__name__}")
        except Exception:
            failed += 1
            print(f"  FAIL  {test.__name__}")
            traceback.print_exc()
    print(f"\ntest_dual_match_confirmation: {passed} passed, {failed} failed, {len(tests)} total")
    raise SystemExit(1 if failed else 0)
