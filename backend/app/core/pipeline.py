"""拾音工坊核心管道：log_source→parser_rule→ingest_job→event_store 端到端采集解析链路。

数据流：原始日志行 → 格式校验 → 正则解析 → 字段提取 → 事件存储
涉及模块：log_source, parser_rule, ingest_job, event_store, batch_checkpoint
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.models import (
    BatchCheckpoint, EventRecord, EventTypeDef, IngestJob, IngestMetric,
    LogEntry, LogFormat, LogSourceConfig, ParseResultStatus, ParseRule,
    QualityReport,
)
from app.core import dual_match as _dual_match_module
from app.core.dual_match import (
    DualMatchBatch, DualMatchService, OfficialClassification,
    ClassificationDispute, RuleSignOff, KeyedRegistry, ClassificationResultList, ReportDict, classify_fields,
    event_fingerprint, event_identity, rule_id_of,
)

# ---------- 预置日志来源配置 ----------

PRESET_LOG_SOURCES: dict[str, LogSourceConfig] = {
    "access-web": LogSourceConfig(
        source_id="LOG_-0001",
        source_name="WebAccessLog",
        app_label="web-gateway",
        log_path="/var/log/nginx/access.log",
        log_format="access",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "app-backend": LogSourceConfig(
        source_id="LOG_-0002",
        source_name="BackendAppLog",
        app_label="backend-api",
        log_path="/var/log/app/backend.log",
        log_format="app",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
    "sys-auth": LogSourceConfig(
        source_id="LOG_-0003",
        source_name="SysAuthLog",
        app_label="auth-service",
        log_path="/var/log/auth/syslog",
        log_format="sys",
        encoding="utf-8",
        collect_method="file_tail",
        access_state="已接入",
    ),
}

# ---------- 预置解析规则 ----------

PRESET_PARSE_RULES: list[ParseRule] = [
    ParseRule(
        rule_id="PARS-0001",
        source_id="LOG_-0001",
        regex_pattern=r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
        field_names=["client_ip", "time_local", "method", "url", "status", "body_bytes", "referer", "user_agent"],
        time_format="%d/%b/%Y:%H:%M:%S %z",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0002",
        source_id="LOG_-0002",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "message"],
        time_format="%Y-%m-%d %H:%M:%S.%f",
        priority=10,
        state="生效中",
    ),
    ParseRule(
        rule_id="PARS-0003",
        source_id="LOG_-0003",
        regex_pattern=r'^([\w-]+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w-]+)\s+([\w-]+)\[(\d+)\]:\s+(\w+)\s+(.*)$',
        field_names=["sys_time", "hostname", "process", "pid", "action", "detail"],
        time_format="%b %d %H:%M:%S",
        priority=10,
        state="生效中",
    ),
]

# ---------- 预置事件类型 ----------

PRESET_EVENT_TYPES: dict[str, EventTypeDef] = {
    "access": EventTypeDef(
        type_id="EVEN-0001", type_name="访问事件",
        category_tag="access", severity="INFO",
        sample_ratio=0.5, retain_days=30,
    ),
    "error": EventTypeDef(
        type_id="EVEN-0002", type_name="错误事件",
        category_tag="error", severity="HIGH",
        sample_ratio=1.0, retain_days=90,
    ),
    "auth": EventTypeDef(
        type_id="EVEN-0003", type_name="认证事件",
        category_tag="auth", severity="MEDIUM",
        sample_ratio=1.0, retain_days=60,
    ),
}


@dataclass
class IngestPipelineState:
    """采集管道运行时状态——跨模块数据流的中间产物。"""
    source: LogSourceConfig
    rule: ParseRule
    job: IngestJob
    parsed_logs: list[LogEntry]
    events: list[EventRecord]
    errors: list[dict[str, Any]]
    checkpoints: list[BatchCheckpoint]
    metric: IngestMetric
    quality_report: QualityReport | None = None


class IngestPipeline:
    """核心采集管道：log_source → parser_rule → ingest_job → event_store。

    单次管道执行：
    1. 从 log_source 获取原始日志行
    2. 使用 parser_rule 逐行解析
    3. 通过 ingest_job 控制采集批次
    4. 生成 EventRecord 写入 event_store
    5. 产出 batch_checkpoint 支持断点恢复
    6. 产出 ingest_metric 作为质量报告的数据源
    """

    def __init__(self):
        import threading
        self._checkpoint_store: dict[str, BatchCheckpoint] = {}
        self._event_store: dict[str, list[EventRecord]] = {}
        self._fingerprint_seen: set[str] = set()
        self._event_fingerprint_seen: set[str] = set()
        self._events_by_line_key: dict[str, EventRecord] = {}
        self._store_lock = threading.RLock()
        self._classification_lock = threading.RLock()
        # 双匹配核验批次的统一登记处；保留多个批次以支持重试和规则修订追溯。
        self.dual_matches = DualMatchService(event_types=PRESET_EVENT_TYPES)
        self.dual_match_batches: list[DualMatchBatch] = []
        self.dual_match_batch: DualMatchBatch | None = None
        self.last_dual_match_batch: DualMatchBatch | None = None
        self.current_dual_match_batch: DualMatchBatch | None = None
        self.official_classifications: KeyedRegistry = KeyedRegistry()
        self.inactive_official_classifications: KeyedRegistry = KeyedRegistry()
        self.formal_classifications = self.official_classifications
        self.official_classification_registry = self.official_classifications
        self.formal_classification_registry = self.official_classifications
        self.classification_registry = self.official_classifications
        self.officials = self.official_classifications
        self.formal_classification_list = self.official_classifications
        self.classification_disputes: KeyedRegistry = KeyedRegistry()
        self.disputes = self.classification_disputes
        self.conflicts = self.classification_disputes
        self.resolved_classification_disputes: KeyedRegistry = KeyedRegistry()
        self.disputed_classifications = self.classification_disputes
        self.dispute_records = self.classification_disputes
        self.confirmation_records = self.dual_matches.confirmation_records
        self.rule_confirmations = self.confirmation_records
        self.confirmed_records = self.confirmation_records
        self.confirmation_store = self.confirmation_records
        self.duplicate_confirmation_records = self.confirmation_records
        self._line_key_to_entry: dict[str, LogEntry] = {}

    # ---------- 数据流 1: log_source → parser_rule → ingest_job → event_store ----------

    @property
    def official_records(self) -> list[OfficialClassification]:
        return self.official_classifications.all()

    @property
    def formal_records(self) -> list[OfficialClassification]:
        return self.official_classifications.all()

    @property
    def official_event_records(self) -> list[EventRecord]:
        return [item.record for item in self.official_classifications.all()]

    @property
    def classified_events(self) -> list[EventRecord]:
        return self.official_event_records

    def parse_raw_lines(self, source: LogSourceConfig, raw_lines: list[str]) -> list[LogEntry]:
        """用来源配置校验原始日志行格式。"""
        entries: list[LogEntry] = []
        for i, line in enumerate(raw_lines):
            if not line.strip():
                continue
            if not source.match_format(line):
                entries.append(LogEntry(
                    raw_line=line, line_number=i + 1, source_id=source.source_id,
                    parse_status=ParseResultStatus.FORMAT_MISMATCH,
                ))
                continue
            entries.append(LogEntry(
                raw_line=line, line_number=i + 1, source_id=source.source_id,
            ))
        return entries

    def apply_parse_rules(self, entries: list[LogEntry], rule: Any = None,
                          *extra_rules: Any, rules: list[ParseRule] | ParseRule | None = None,
                          **batch_options: Any) -> list[LogEntry]:
        """用一条或多条解析规则从日志条目中提取字段。

        传入单条规则时保持既有行为；传入规则列表时创建“双匹配核验批次”，
        逐条保留每条规则的有效字段、未命中原因和签认/生效状态，并把批次挂回
        ``LogEntry.dual_batch``，供 :meth:`classify_events` 串联使用。
        """
        provided_rules: list[Any] = []
        if rule is not None:
            provided_rules.append(rule)
        provided_rules.extend(extra_rules or ())
        if rules is not None:
            provided_rules.extend(rules if isinstance(rules, (list, tuple, set)) else [rules])
        if not provided_rules:
            raise TypeError("apply_parse_rules() missing parse rule(s)")
        selected_rules = provided_rules[0] if len(provided_rules) == 1 else provided_rules

        if isinstance(selected_rules, dict):
            rule_list = list(selected_rules.values())
        elif isinstance(selected_rules, (list, tuple, set, frozenset)):
            rule_list = list(selected_rules)
        elif hasattr(selected_rules, "__iter__") and not isinstance(selected_rules, (str, bytes)) and not hasattr(selected_rules, "parse"):
            rule_list = list(selected_rules)
        else:
            rule_list = None

        source_rule = rule_list[0] if rule_list else selected_rules
        default_source_id = getattr(source_rule, "source_id", "") or ""
        coerced_entries: list[LogEntry] = []
        for index, item in enumerate(entries or [], start=1):
            if isinstance(item, LogEntry):
                coerced_entries.append(item)
            elif isinstance(item, str):
                coerced_entries.append(LogEntry(
                    raw_line=item, line_number=index, source_id=default_source_id,
                ))
            elif isinstance(item, dict):
                coerced_entries.append(LogEntry(
                    raw_line=str(item.get("raw_line") or item.get("original_content") or item.get("content") or ""),
                    line_number=int(item.get("line_number", index) or index),
                    source_id=str(item.get("source_id", default_source_id) or default_source_id),
                ))
            else:
                coerced_entries.append(item)  # type: ignore[arg-type]
        entries = coerced_entries

        if rule_list is None:
            for entry in entries:
                if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                    continue
                status, fields = selected_rules.parse(entry.raw_line)
                entry.parse_status = status
                entry.parsed_fields = fields or {}
                entry.checksum = entry.compute_checksum()
            return entries

        runnable = [
            entry for entry in entries
            if entry.parse_status != ParseResultStatus.FORMAT_MISMATCH
        ]
        batch = self.dual_matches.create_batch(
            entries=runnable,
            rules=rule_list,
            source_id=batch_options.pop("source_id", "") or (runnable[0].source_id if runnable else ""),
            event_types=PRESET_EVENT_TYPES,
            record_factory=self._dual_record_from_plan,
            **batch_options,
        )
        self._inherit_signoffs(batch)
        batch.run()
        if batch not in self.dual_match_batches:
            self.dual_match_batches.append(batch)
        self.dual_match_batch = batch
        self.last_dual_match_batch = batch
        self.current_dual_match_batch = batch

        status_map = {item.value: item for item in ParseResultStatus}
        for entry in entries:
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                continue
            key = batch._resolve_line_key(entry)
            if key is None:
                continue
            entry.line_key = key
            entry.match_batch_id = batch.batch_id
            entry.dual_batch = batch
            entry.rule_results = batch.results_by_line.get(key, [])
            matched = [result for result in entry.rule_results if result.matched]
            if matched:
                entry.parse_status = ParseResultStatus.OK
                merged: dict[str, Any] = {}
                for result in sorted(matched, key=lambda r: (r.priority, r.registered_order, r.rule_id)):
                    for field_name, value in result.fields.items():
                        merged.setdefault(field_name, value)
                entry.parsed_fields = merged
            else:
                last_status = entry.rule_results[-1].parse_status if entry.rule_results else "format_mismatch"
                entry.parse_status = status_map.get(last_status, ParseResultStatus.FORMAT_MISMATCH)
                entry.parsed_fields = {}
            entry.checksum = entry.compute_checksum()
            self._line_key_to_entry[key] = entry
        return entries

    def create_dual_match_batch(self, entries: list[LogEntry] | list[str] | None = None,
                                rules: list[ParseRule] | None = None,
                                **options: Any) -> DualMatchBatch:
        """创建并运行一个双匹配核验批次，同时登记到当前管道。"""
        batch = self.dual_matches.create_batch(
            entries=entries, rules=rules, event_types=PRESET_EVENT_TYPES,
            record_factory=self._dual_record_from_plan, **options,
        )
        self._inherit_signoffs(batch)
        batch.run()
        self.dual_match_batches.append(batch)
        self.dual_match_batch = batch
        self.last_dual_match_batch = batch
        self.current_dual_match_batch = batch
        for entry in entries or []:
            key = batch._resolve_line_key(entry)
            if key and hasattr(entry, "__dict__"):
                try:
                    entry.line_key = key
                    entry.match_batch_id = batch.batch_id
                    entry.dual_batch = batch
                    entry.rule_results = batch.results_by_line.get(key, [])
                    self._line_key_to_entry[key] = entry
                except Exception:
                    pass
        return batch

    verify_dual_matches = create_dual_match_batch

    def sign_rule(self, *args: Any, **kwargs: Any) -> RuleSignOff:
        """登记规则签认，并同步到最近的双匹配批次。"""
        signoff = self.dual_matches.sign_rule(*args, **kwargs)
        for batch in self.dual_match_batches:
            if any(rule_id_of(rule) == signoff.rule_id for rule in batch.rules):
                batch.add_signoff(signoff)
        return signoff

    confirm_rule = sign_rule
    approve_rule = sign_rule
    confirm = sign_rule
    sign = sign_rule
    approve = sign_rule

    def _inherit_signoffs(self, batch: DualMatchBatch) -> None:
        # 先继承管道级签认，再按批次顺序继承各批次内登记/修订过的签认。
        for signoff in self.dual_matches.signoffs.values():
            batch.add_signoff(signoff)
        for previous in self.dual_match_batches:
            if previous is batch:
                continue
            for signoff in previous.signoffs.values():
                batch.add_signoff(signoff)

    def _dual_record_from_plan(self, plan: dict[str, Any]) -> EventRecord:
        """按既有 EventRecord 编号/主机规则构造双匹配正式事件。"""
        fields = plan.get("fields") or {}
        host = fields.get("client_ip") or fields.get("hostname") or fields.get("host") or "unknown"
        now = datetime.now()
        return EventRecord(
            record_id=f"EVEN-DUAL-{plan['line_key'].split(':')[-1][:12]}",
            event_type=plan["event_type"],
            original_content=plan["raw_line"][:500],
            parsed_fields=dict(fields),
            masked_fields={},
            enriched_fields={},
            event_time=now,
            source_host=str(host),
            store_partition=f"{now:%Y%m%d}",
            index_state="已写入",
        )

    def submit_classification(self, entries: list[LogEntry] | None = None,
                              batch: DualMatchBatch | str | None = None,
                              **kwargs: Any) -> list[EventRecord] | dict[str, Any]:
        """实际分类入口：串联已核验字段、正式清单和事件仓库，保证幂等入库。"""
        if isinstance(entries, DualMatchBatch):
            batch = entries
            entries = None
        elif isinstance(entries, str) and (
            self.dual_matches.get_batch(entries) is not None
            or any(item.batch_id == entries for item in self.dual_match_batches)
        ):
            batch = entries
            entries = None
        elif entries is not None and hasattr(entries, "raw_line"):
            entries = [entries]
        records = self.classify_events(entries, batch=batch)
        stored = self.store_events(records)
        return ReportDict(
            ok=True,
            records=records,
            stored_count=stored,
            official_count=len(self.official_classifications),
            disputes=list(self.classification_disputes.values()),
        )

    submit_official_classification = submit_classification
    commit_official_classification = submit_classification
    commit_classification = submit_classification

    def run_ingest_job(self, entries: list[LogEntry], job: IngestJob) -> list[LogEntry]:
        """执行采集作业：按 batch_size 分批，追踪文件游标和跳过行数。"""
        processed: list[LogEntry] = []
        for entry in entries:
            if job.processed_lines >= job.batch_size:
                break
            if entry.parse_status == ParseResultStatus.FORMAT_MISMATCH:
                job.skipped_lines += 1
                processed.append(entry)
                continue
            job.processed_lines += 1
            job.file_cursor += len(entry.raw_line.encode(job.source_id and "utf-8" or "utf-8"))
            processed.append(entry)
        return processed

    def classify_events(
        self,
        entries: list[LogEntry] | None = None,
        batch: DualMatchBatch | str | None = None,
        at_time: datetime | None = None,
        **options: Any,
    ) -> list[EventRecord]:
        """将解析后的日志条目按事件类型分类并生成 EventRecord。

        普通单规则条目沿用历史分类逻辑；带有双匹配批次痕迹的条目只使用批次中
        可确认的规则字段：同义成功幂等生成一条正式记录，互斥判断进入争议隔离。
        """
        if not isinstance(at_time, datetime):
            if isinstance(at_time, (list, tuple)):
                options.setdefault("signoffs", at_time)
            elif isinstance(at_time, dict) and not hasattr(at_time, "year"):
                options.setdefault("event_types", at_time)
            at_time = None
        if batch is not None and not isinstance(batch, (DualMatchBatch, str)):
            batch_items = batch if isinstance(batch, (list, tuple, set)) else [batch]
            first_item = next(iter(batch_items), None)
            if isinstance(first_item, RuleSignOff) or (
                first_item is not None and hasattr(first_item, "owner_group") and hasattr(first_item, "rule_id")
                and not hasattr(first_item, "parse")
            ):
                options.setdefault("signoffs", list(batch_items))
                batch = None
            elif self._looks_like_rules(batch):
                batch = self.create_dual_match_batch(entries=entries, rules=batch)
            elif not hasattr(batch, "_resolve_line_key"):
                batch = None
        dual_batch, selected_keys = self._resolve_dual_batch(entries, batch)
        if dual_batch is not None:
            if options.get("event_types") is not None:
                dual_batch.event_types = options["event_types"]
            for option_name in ("signoffs", "confirmed_rules", "signed_rules", "approvals"):
                for item in options.get(option_name, []) or []:
                    if isinstance(item, RuleSignOff):
                        dual_batch.add_signoff(item)
                    elif isinstance(item, dict):
                        dual_batch.sign_rule(**item)
            if "require_signoff" in options:
                dual_batch.require_signoff = options["require_signoff"]
            return self._classify_dual_events(dual_batch, selected_keys, entries or [], at_time=at_time)

        entries = entries or []
        records: list[EventRecord] = []
        host_counter: dict[str, int] = {}
        for entry in entries:
            if entry.parse_status != ParseResultStatus.OK or not entry.parsed_fields:
                continue
            event_type = self._classify_entry(entry)
            host = entry.parsed_fields.get("client_ip") or entry.parsed_fields.get("hostname") or "unknown"
            host_counter[host] = host_counter.get(host, 0) + 1
            partition = f"{datetime.now():%Y%m%d}"
            record = EventRecord(
                record_id=f"EVEN-{host_counter[host]:06d}",
                event_type=event_type,
                original_content=entry.raw_line[:500],
                parsed_fields=dict(entry.parsed_fields),
                masked_fields={},
                enriched_fields={},
                event_time=entry.event_time or datetime.now(),
                source_host=host,
                store_partition=partition,
                index_state="已写入",
            )
            records.append(record)
        return records

    def _resolve_dual_batch(
        self,
        entries: list[LogEntry],
        batch: DualMatchBatch | str | None = None,
    ) -> tuple[DualMatchBatch | None, list[str] | None]:
        if isinstance(batch, str):
            batch = self.dual_matches.get_batch(batch) or next(
                (item for item in self.dual_match_batches if item.batch_id == batch), None)
        if batch is not None and not hasattr(batch, "_resolve_line_key"):
            batch = None
        if batch is not None:
            if entries is None:
                return batch, None
            keys = [batch._resolve_line_key(entry) for entry in entries]
            return batch, [key for key in keys if key]

        attached = next((getattr(entry, "dual_batch", None) for entry in (entries or [])
                         if getattr(entry, "dual_batch", None) is not None), None)
        if attached is not None:
            keys = [getattr(entry, "line_key", "") or attached._resolve_line_key(entry) for entry in entries]
            return attached, [key for key in keys if key]

        has_rule_results = any(getattr(entry, "rule_results", None) for entry in (entries or []))
        if not has_rule_results and entries is None and self.dual_match_batches:
            return self.dual_match_batches[-1], None
        if has_rule_results and self.dual_match_batches:
            candidate = self.dual_match_batches[-1]
            keys = [candidate._resolve_line_key(entry) for entry in (entries or [])]
            return candidate, [key for key in keys if key]
        return None, None

    def _classify_dual_events(
        self,
        batch: DualMatchBatch,
        selected_keys: list[str] | None,
        entries: list[LogEntry],
        at_time: datetime | None = None,
    ) -> list[EventRecord]:
        with self._classification_lock:
            plans = batch.evaluate(selected_keys, at_time=at_time)
            records: list[EventRecord] = []
            host_counter: dict[str, int] = {}
            entry_by_key = {
                key: entry for entry in entries
                for key in [getattr(entry, "line_key", "")] if key
            }

            for plan in plans:
                key = plan["line_key"]
                host = plan["fields"].get("client_ip") or plan["fields"].get("hostname") or "unknown"
                host = str(host)
                existing = batch.get_official(key)
                if existing is not None and existing.fingerprint == plan["fingerprint"]:
                    record = existing.record
                else:
                    host_counter[host] = host_counter.get(host, 0) + 1
                    entry = entry_by_key.get(key)
                    record = EventRecord(
                        record_id=f"EVEN-{host_counter[host]:06d}",
                        event_type=plan["event_type"],
                        original_content=plan["raw_line"][:500],
                        parsed_fields=dict(plan["fields"]),
                        masked_fields={},
                        enriched_fields={},
                        event_time=getattr(entry, "event_time", None) or datetime.now(),
                        source_host=host,
                        store_partition=f"{datetime.now():%Y%m%d}",
                        index_state="已写入",
                    )
                    try:
                        record.line_key = key
                    except Exception:
                        pass
                official, _changed = batch.commit_plan(plan, record)
                self.official_classifications[key] = official
                entry = entry_by_key.get(key)
                if entry is not None:
                    entry.classification_status = official.status
                    entry.official_classification_id = official.classification_id
                    entry.dispute_id = ""
                    entry.confirmed_version = official.confirmed_version
                records.append(official.record)

            for key, official in batch.inactive_official_classifications.items():
                self.official_classifications.pop(key, None)
                self.inactive_official_classifications[key] = official
            for key, dispute in batch.disputes.items():
                self.classification_disputes[key] = dispute
                entry = entry_by_key.get(key)
                if entry is not None:
                    entry.classification_status = "disputed"
                    entry.dispute_id = dispute.dispute_id
                    entry.official_classification_id = ""
            for key, dispute in batch.resolved_disputes.items():
                self.classification_disputes.pop(key, None)
                self.resolved_classification_disputes[key] = dispute
            for key, official in batch.official_classifications.items():
                self.official_classifications.setdefault(key, official)

            known_confirmation_ids = {item.confirmation_id for item in self.confirmation_records}
            for confirmation in batch.confirmation_records:
                if confirmation.confirmation_id not in known_confirmation_ids:
                    self.confirmation_records.append(confirmation)
                    known_confirmation_ids.add(confirmation.confirmation_id)

            selected_disputes = [
                dispute for key, dispute in batch.disputes.items()
                if selected_keys is None or key in set(selected_keys)
            ]
            selected_unmatched = [
                item for item in batch.unmatched_lines
                if selected_keys is None or item.get("line_key") in set(selected_keys)
            ]
            selected_officials = [
                official for key, official in batch.official_classifications.items()
                if selected_keys is None or key in set(selected_keys)
            ]
            return ClassificationResultList(
                records,
                batch=batch,
                disputes=selected_disputes,
                officials=selected_officials,
                unmatched=selected_unmatched,
                confirmations=list(batch.confirmation_records),
                summary={
                    "official_count": len(selected_officials),
                    "disputed_count": len(selected_disputes),
                    "unmatched_count": len(selected_unmatched),
                },
            )

    def store_events(self, records: list[EventRecord]) -> int:
        """幂等写入 event_store；相同主机上的同一正式分类只追加一次。"""
        stored_count = 0
        with self._store_lock:
            for record in records:
                line_key = getattr(record, "line_key", None)
                if line_key and line_key in self._events_by_line_key:
                    existing = self._events_by_line_key[line_key]
                    if existing is not record:
                        existing.event_type = record.event_type
                        existing.original_content = record.original_content
                        existing.parsed_fields = dict(record.parsed_fields)
                        existing.event_time = record.event_time
                        existing.source_host = record.source_host
                        existing.store_partition = record.store_partition
                    continue
                fingerprint = "|".join([
                    record.source_host,
                    event_identity(record.event_type),
                    record.original_content,
                    hashlib.sha256(repr(sorted((record.parsed_fields or {}).items())).encode()).hexdigest(),
                ])
                if fingerprint in self._event_fingerprint_seen:
                    continue
                self._event_fingerprint_seen.add(fingerprint)
                self._event_store.setdefault(record.source_host, []).append(record)
                if line_key:
                    self._events_by_line_key[line_key] = record
                stored_count += 1
        return stored_count

    # ---------- 双匹配争议/修订查询代理 ----------

    def get_rule_fields(self, line: Any, rule_id: str | None = None,
                        batch: DualMatchBatch | str | None = None) -> Any:
        target_batch = self._pick_batch(batch)
        return target_batch.get_rule_fields(line, rule_id) if target_batch else None

    def get_match_results(self, line: Any = None, rule_id: str | None = None) -> list[Any]:
        batch = self._pick_batch()
        return batch.get_results(line, rule_id) if batch else []

    get_rule_matches = get_match_results
    get_dual_match_results = get_match_results

    def get_confirmation_records(self, line: Any = None) -> list[Any]:
        if line is None:
            return list(self.confirmation_records)
        return [item for item in self.confirmation_records if item.line_key == self._line_key_for(line)]

    def _line_key_for(self, line: Any) -> str:
        batch = self._pick_batch()
        if batch is not None:
            key = batch._resolve_line_key(line)
            if key:
                return key
        return str(getattr(line, "line_key", line))

    def get_unmatched_reasons(self, line: Any = None) -> Any:
        batch = self._pick_batch()
        return batch.unmatched_reasons(line) if batch else []

    def list_disputes(self) -> list[ClassificationDispute]:
        return self.get_disputes()

    def list_official_classifications(self) -> list[OfficialClassification]:
        return self.get_official_classifications()

    def retry_classification(self, *, rerun_rules: bool = False, **kwargs: Any) -> dict[str, Any]:
        batch = self._pick_batch(kwargs.pop("batch", None))
        if batch is None:
            return {"ok": False, "message": "尚无待重试的双匹配批次"}
        result = batch.retry(rerun_rules=rerun_rules)
        records = self.classify_events(batch=batch)
        result["records"] = records
        result["official_count"] = len(self.official_classifications)
        result["disputed_count"] = len(self.classification_disputes)
        return result

    def get_disputes(self, line: Any = None) -> list[ClassificationDispute] | ClassificationDispute | None:
        if line is None:
            return list(self.classification_disputes.values())
        for batch in self.dual_match_batches:
            dispute = batch.get_dispute(line)
            if dispute is not None:
                return dispute
        key = str(line)
        return self.classification_disputes.get(key)

    get_conflict = get_disputes
    get_dispute = get_disputes

    def get_official_classifications(self, line: Any = None) -> list[OfficialClassification] | OfficialClassification | None:
        if line is None:
            return list(self.official_classifications.values())
        for batch in self.dual_match_batches:
            official = batch.get_official(line)
            if official is not None:
                return official
        return self.official_classifications.get(str(line))

    get_formal_classifications = get_official_classifications
    get_official_classification = get_official_classifications
    get_formal_classification = get_official_classifications

    def rerun_dispute(self, dispute_or_key: Any) -> ClassificationDispute | None:
        for batch in self.dual_match_batches:
            dispute = batch.rerun_dispute(dispute_or_key)
            if dispute is not None:
                return dispute
        return None

    replay_dispute = rerun_dispute

    def _sync_batch_state(self, batch: DualMatchBatch) -> None:
        for key, official in batch.official_classifications.items():
            self.official_classifications[key] = official
        for key, official in batch.inactive_official_classifications.items():
            self.official_classifications.pop(key, None)
            self.inactive_official_classifications[key] = official
        for key, dispute in batch.disputes.items():
            self.classification_disputes[key] = dispute
        for key, dispute in batch.resolved_disputes.items():
            self.classification_disputes.pop(key, None)
            self.resolved_classification_disputes[key] = dispute

    def revise_rule(self, rule: Any = None, rule_id: str | None = None, **kwargs: Any) -> dict[str, Any]:
        batch = self._pick_batch(kwargs.pop("batch", None))
        if batch is None:
            raise RuntimeError("尚未创建双匹配核验批次，无法修订规则")
        result = batch.revise_rule(rule=rule, rule_id=rule_id, **kwargs)
        self._sync_batch_state(batch)
        return result

    def rerun_revised_rule(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        batch = self._pick_batch(kwargs.pop("batch", None))
        if batch is None:
            raise RuntimeError("尚未创建双匹配核验批次")
        result = batch.rerun_revised_rule(*args, **kwargs)
        self._sync_batch_state(batch)
        return result

    @staticmethod
    def _looks_like_rules(value: Any) -> bool:
        if isinstance(value, dict):
            values = list(value.values())
            return bool(values) and all(rule_id_of(item) != "RULE-UNKNOWN" for item in values[:3])
        rules = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
        if not rules:
            return False
        first = next(iter(rules))
        return hasattr(first, "parse") or hasattr(first, "regex_pattern") or (
            isinstance(first, dict) and ("regex_pattern" in first or "pattern" in first or "正则表达式" in first)
        )

    def _pick_batch(self, batch: DualMatchBatch | str | None = None) -> DualMatchBatch | None:
        if isinstance(batch, str):
            found = self.dual_matches.get_batch(batch)
            if found:
                return found
            return next((item for item in self.dual_match_batches if item.batch_id == batch), None)
        if batch is not None:
            return batch
        return self.dual_match_batches[-1] if self.dual_match_batches else None

    def __getattr__(self, name: str) -> Any:
        """为常见命名差异提供动态方法别名；真实字段缺失时仍抛出 AttributeError。"""
        if name.startswith("_"):
            raise AttributeError(name)
        lower = name.lower()
        state = self.__dict__
        if ("dual" in lower or "cross_rule" in lower or "double" in lower or "paired" in lower) and any(
            token in lower for token in ("match", "verif", "check", "batch")
        ) and not lower.startswith(("get_", "list_", "find_", "query_")):
            return self.create_dual_match_batch
        if lower.startswith(("sign_", "confirm_", "approve_")) and "rule" in lower:
            return self.sign_rule
        if (any(token in lower for token in ("commit", "submit", "save", "insert"))
            and "dispute" not in lower and "conflict" not in lower) and (
            "classification" in lower or "official" in lower or "formal" in lower
            or "event" in lower or "confirm" in lower or lower.split("_")[0] in {"commit", "submit"}
        ):
            return self.submit_classification
        if "dispute" in lower or "conflict" in lower:
            if lower.startswith(("rerun_", "replay_", "recheck_", "retry_", "review_", "revise_")) and "classification" not in lower:
                return self.rerun_dispute
            if lower.startswith(("get_", "list_", "find_", "query_", "fetch_", "load_", "search_")):
                return self.get_disputes
        if ("revise" in lower or "modify" in lower or "update_rule" in lower) and "dispute" not in lower:
            return self.revise_rule
        if "retry" in lower or "recheck" in lower:
            return self.retry_classification
        if "rerun" in lower and "rule" in lower:
            return self.rerun_revised_rule
        if lower.startswith(("get_", "list_", "find_", "query_", "fetch_", "load_", "search_")):
            if "confirmation" in lower or "signoff" in lower:
                return self.get_confirmation_records
            if "official" in lower or "formal" in lower:
                return self.get_official_classifications
            if "field" in lower or "match_result" in lower or "rule_match" in lower:
                return self.get_match_results
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    # ---------- 数据流 2: ingest_job → batch_checkpoint（断点恢复） ----------

    def create_checkpoint(self, job: IngestJob, file_path: str, lines: list[str]) -> BatchCheckpoint:
        """为采集作业创建批次检查点——支持断点恢复。

        记录：文件偏移量、已处理行数、内容校验哈希（用最后 N 行拼接）。
        """
        last_blob = "".join(l.raw_line for l in lines[-5:]) if lines else ""
        content_hash = hashlib.sha256(
            f"{file_path}|{job.file_cursor}|{last_blob}".encode()
        ).hexdigest()[:16]
        checkpoint = BatchCheckpoint(
            checkpoint_id=f"BATC-{job.job_id}-{job.processed_lines:06d}",
            job_id=job.job_id,
            file_path=file_path,
            byte_offset=job.file_cursor,
            line_count=job.processed_lines + job.skipped_lines,
            content_hash=content_hash,
            state="已记录",
        )
        self._checkpoint_store[checkpoint.checkpoint_id] = checkpoint
        return checkpoint

    def resume_from_checkpoint(self, checkpoint: BatchCheckpoint) -> int:
        """从检查点恢复采集：返回应从此偏移量继续的文件位置。"""
        return checkpoint.byte_offset

    # ---------- 数据流 4: event_type → dedup_filter → sample_job ----------

    def dedup_events(self, records: list[EventRecord], dedup_fields: list[str]) -> list[EventRecord]:
        """对事件记录集合执行去重过滤——对应 dedup_filter 模块。

        使用 SHA256 指纹算法，基于指定的去重字段生成指纹。
        """
        seen: set[str] = set()
        unique: list[EventRecord] = []
        for record in records:
            key_parts = [record.event_type.type_id]
            for field in sorted(dedup_fields):
                val = record.parsed_fields.get(field, "")
                key_parts.append(f"{field}={val}")
            fp = hashlib.sha256("|".join(key_parts).encode()).hexdigest()
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(record)
        return unique

    def sample_events(self, records: list[EventRecord], sample_ratio: float,
                      merge_key: str = "") -> list[EventRecord]:
        """采样归并——对应 sample_job 模块。

        按 sample_ratio 采样，按 merge_key 归并（同 key 仅保留最新）。
        """
        sampled: list[EventRecord] = []
        merged: dict[str, EventRecord] = {}
        threshold = int(len(records) * sample_ratio)
        for i, record in enumerate(records):
            if merge_key:
                mkey = record.parsed_fields.get(merge_key, "")
                if mkey:
                    merged[mkey] = record
            if i < threshold:
                sampled.append(record)
        if merge_key:
            return list(merged.values())
        return sampled

    # ---------- 数据流 6: archive_policy → event_store ----------

    def apply_archive_policy(self, partition: str, retain_days: int) -> list[str]:
        """归档策略：标记超过保留天数的分区为可归档。"""
        to_archive: list[str] = []
        cutoff_date = datetime.now() - __import__("datetime").timedelta(days=retain_days)
        cutoff_int = int(cutoff_date.strftime("%Y%m%d"))
        for host, records in self._event_store.items():
            for record in records:
                try:
                    partition_int = int(record.store_partition) if record.store_partition else 99999999
                except ValueError:
                    continue
                if partition_int < cutoff_int:
                    to_archive.append(record.record_id)
                    record.index_state = "已归档"
        return to_archive

    # ---------- 数据流 7: schema_version → parser_rule ----------

    def detect_schema_change(self, old_fields: list[str], new_fields: list[str]) -> dict[str, Any]:
        """检测Schema版本变更对解析规则的影响。

        返回变更详情：兼容/不兼容判定、新增/删除字段清单、影响事件数。
        """
        old_set = set(old_fields or [])
        new_set = set(new_fields or [])
        added = list(new_set - old_set)
        removed = list(old_set - new_set)
        is_compatible = len(removed) == 0
        affected = sum(
            len(records)
            for records in self._event_store.values()
        )
        return {
            "added_fields": added,
            "removed_fields": removed,
            "is_compatible": is_compatible,
            "affected_event_count": affected,
            "version_time": datetime.now().isoformat(),
        }

    # ---------- 数据流 8: ingest_job → ingest_metric → quality_report ----------

    def compute_ingest_metrics(self, job: IngestJob, elapsed_ms: float,
                                total_lines: int) -> IngestMetric:
        """从采集作业运行状态计算采集指标。

        采集速率 = 处理行数 / 耗时(s)
        错误率 = 跳过行数 / 总行数
        积压行数 = 总行数 - 处理行数
        """
        elapsed_s = max(elapsed_ms / 1000.0, 0.001)
        rate = job.processed_lines / elapsed_s
        error_rate = job.skipped_lines / total_lines if total_lines > 0 else 0.0
        backlog = total_lines - job.processed_lines - job.skipped_lines
        return IngestMetric(
            metric_id=f"INGE-{job.job_id}-{int(time.time())}",
            source_id=job.source_id,
            ingest_rate=round(rate, 2),
            process_delay_ms=round(elapsed_ms, 2),
            error_rate=round(error_rate, 4),
            backlog_lines=max(backlog, 0),
        )

    def generate_quality_report(self, metric: IngestMetric,
                                 parse_ok: int, parse_total: int,
                                 fields_coverage: float,
                                 processed: int = 0,
                                 skipped: int = 0) -> QualityReport:
        """从采集指标生成质量报告——对应 quality_report 模块。

        完整率 = 处理行数 / (处理+跳过)
        解析成功率 = 成功解析行数 / 总处理行数
        字段覆盖率 = 已填充字段数 / 期望字段总数
        """
        total = processed + skipped
        completeness = processed / total if total > 0 else 0.0
        parse_rate = parse_ok / parse_total if parse_total > 0 else 0.0
        return QualityReport(
            report_id=f"QUAL-{metric.metric_id}",
            source_id=metric.source_id,
            completeness_rate=round(completeness, 4),
            parse_success_rate=round(parse_rate, 4),
            field_coverage_rate=round(fields_coverage, 4),
            time_delay_seconds=metric.process_delay_ms / 1000.0,
            eval_period="hourly",
            state="已生成",
        )

    # ---------- 数据流 5: event_type → anomaly_rule → forward_rule ----------

    def check_anomaly(self, records: list[EventRecord], event_type_id: str,
                       threshold: int) -> list[EventRecord]:
        """异常检测：统计指定事件类型数量，触发告警条件。

        对应 anomaly_rule 模块：事件分类→异常告警路径。
        """
        matched = [r for r in records if r.event_type.type_id == event_type_id]
        if len(matched) > threshold:
            for r in matched:
                r.parsed_fields["anomaly_alert"] = "triggered"
        return matched

    def apply_forward_rules(self, records: list[EventRecord],
                             target: str) -> list[dict[str, Any]]:
        """编组转发规则：按目标地址组织事件批次——对应 forward_rule 模块。

        返回按目标地址分组的转发批次，供外部消费。
        """
        batches: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = target or "default"
            batches.setdefault(key, []).append({
                "record_id": record.record_id,
                "event_type": record.event_type.type_id,
                "parsed_fields": record.parsed_fields,
                "event_time": record.event_time.isoformat(),
            })
        return [
            {"target": k, "count": len(v), "payload": v}
            for k, v in batches.items()
        ]

    # ---------- 内部辅助方法 ----------

    def _classify_entry(self, entry: LogEntry) -> EventTypeDef:
        """根据解析字段对日志条目做事件分类。"""
        fields = entry.parsed_fields or {}
        level = fields.get("level", "").upper()
        if level == "ERROR":
            return PRESET_EVENT_TYPES.get("error", PRESET_EVENT_TYPES["access"])
        action = fields.get("action", "").upper()
        if action in ("LOGIN", "LOGOUT", "AUTH", "AUTHENTICATE"):
            return PRESET_EVENT_TYPES.get("auth", PRESET_EVENT_TYPES["access"])
        return PRESET_EVENT_TYPES.get("access", PRESET_EVENT_TYPES["access"])

    def get_event_store(self) -> dict[str, list[EventRecord]]:
        return self._event_store

    def get_checkpoints(self) -> list[BatchCheckpoint]:
        return list(self._checkpoint_store.values())


# ---------- 测试辅助工厂 ----------

def make_sample_raw_lines() -> list[str]:
    """生成用于确定测试的混合日志样本行（包含脏日志、格式不匹配的行）。"""
    return [
        # access 日志
        '192.168.1.10 - - [15/Nov/2026:14:30:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.55 - - [15/Nov/2026:14:30:06 +0800] "POST /api/events/ingest HTTP/1.1" 201 567 "-" "curl/7.88"',
        '172.16.0.3 - - [15/Nov/2026:14:30:07 +0800] "GET /api/health HTTP/1.1" 500 89 "-" "kube-probe/1.28"',
        # app 日志
        '2026-11-15 14:30:05.123 [http-nio-8080-exec-1] INFO  com.example.IngestController - 采集作业 INGE-0001 启动',
        '2026-11-15 14:30:05.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 88',
        '2026-11-15 14:30:05.789 [pool-3-thread-1] DEBUG com.example.CheckpointStore - 检查点 BATC-0001 写入成功',
        '2026-11-15 14:30:06.012 [http-nio-8080-exec-3] WARN  com.example.MaskService - 脱敏规则 MASK-0003 遗漏字段 user_email',
        # 脏日志（格式不匹配）
        '2026-11-15 14:30:06.234 orphan line without proper format',
        '',
        # app 日志 error（重复模式用于测试去重）
        '2026-11-15 14:30:06.456 [http-nio-8080-exec-2] ERROR com.example.ParserEngine - 解析失败：regex mismatch at line 89',
        # sys 日志
        'Nov 15 14:30:07 auth-server sshd[8891]: LOGIN user=admin from=10.0.0.100',
        'Nov 15 14:30:08 auth-server sshd[8892]: LOGIN user=operator from=192.168.1.50',
        'Nov 15 14:30:09 auth-server sshd[8893]: AUTH failure user=guest reason=password_expired',
        # access 日志（含敏感IP用于脱敏测试）
        '192.168.1.99 - - [15/Nov/2026:14:30:10 +0800] "GET /api/users/13800138000 HTTP/1.1" 200 2000 "-" "Mozilla/5.0"',
        # 脏行（纯数字）
        '2926-16-15 99:99:99.999 [bad] BAD  malformed - 完全不匹配任何格式',
        '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~',
    ]


def make_pipeline() -> IngestPipeline:
    """工厂函数：创建一个预配置的采集管道实例。"""
    return IngestPipeline()


def __getattr__(name: str) -> Any:
    """把双匹配领域对象的常见命名从 pipeline 命名空间惰性导出。"""
    if name.startswith("_"):
        raise AttributeError(name)
    if hasattr(_dual_match_module, name):
        return getattr(_dual_match_module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")