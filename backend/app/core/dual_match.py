"""双匹配核验、签认分类、争议隔离与规则修订重放。

本模块不依赖 FastAPI 或数据库，便于在采集管道和测试中直接使用。核心不变量：

* 每条原行都有稳定 ``line_key``，未命中、争议、正式分类均可追溯；
* 每条规则对原行的原始捕获字段和未命中原因单独留痕；
* 两份成功若分类含义相同，只形成一条正式分类，但保留两条规则签认；
* 两份成功若给出互斥分类且没有约定最终分类权，进入争议隔离；
* 正式分类按 ``line_key + 分类指纹`` 幂等入库，并发提交也只有一条；
* 规则修订只重跑曾经真正命中该规则的原行，无争议且未受影响的行版本不变。
"""
from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from app.core.models import EventRecord, EventTypeDef

ACTIVE_RULE_STATES = {"生效中", "有效", "已生效", "active", "effective", "approved", "confirmed"}
SIGNED_STATES = {"已签认", "签认通过", "已确认", "confirmed", "signed", "approved"}
REVOKED_STATES = {"已撤下", "已撤回", "已废弃", "已停用", "revoked", "withdrawn", "deprecated", "inactive"}

DEFAULT_EVENT_TYPES: dict[str, EventTypeDef] = {
    "access": EventTypeDef(
        type_id="EVEN-0001", type_name="访问事件", category_tag="access", severity="INFO",
        sample_ratio=0.5, retain_days=30,
    ),
    "error": EventTypeDef(
        type_id="EVEN-0002", type_name="错误事件", category_tag="error", severity="HIGH",
        sample_ratio=1.0, retain_days=90,
    ),
    "auth": EventTypeDef(
        type_id="EVEN-0003", type_name="认证事件", category_tag="auth", severity="MEDIUM",
        sample_ratio=1.0, retain_days=60,
    ),
}

_ERROR_WORDS = {"ERROR", "ERR", "FATAL", "CRITICAL", "故障", "错误"}
_AUTH_WORDS = {"LOGIN", "LOGOUT", "AUTH", "AUTHENTICATE", "SIGNIN", "SIGN-IN", "登录", "登陆", "认证", "账号审计"}


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now()


def _short_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:length]


def _stable_line_key(source_id: str, line_number: int | None, raw_line: str,
                     explicit: str | None = None) -> str:
    if explicit:
        return str(explicit)
    raw_hash = _short_hash(raw_line, 16)
    return f"{source_id or 'SRC'}:{line_number or 0}:{raw_hash}"


def _attr(obj: Any, names: tuple[str, ...], default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        for name in names:
            if name in obj and obj[name] not in (None, ""):
                return obj[name]
        return default
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value not in (None, ""):
                return value
    return default


def rule_id_of(rule: Any) -> str:
    value = _attr(rule, ("rule_id", "id", "方案编号", "规则编号", "code", "key"))
    return str(value) if value not in (None, "") else "RULE-UNKNOWN"


def rule_pattern_of(rule: Any) -> str | re.Pattern[str] | None:
    pattern = _attr(rule, ("regex_pattern", "pattern", "regex", "正则表达式", "正则", "expression"))
    return pattern


def rule_field_names_of(rule: Any) -> list[str]:
    names = _attr(rule, ("field_names", "fields", "field_definitions", "字段定义", "字段", "capture_fields"))
    if names is None:
        return []
    if isinstance(names, str):
        return [part.strip() for part in re.split(r"[,，;；\s]+", names) if part.strip()]
    if isinstance(names, dict):
        return [str(k) for k in names]
    return [str(name) for name in names]


def rule_priority_of(rule: Any, default: int = 100) -> int:
    value = _attr(rule, ("priority", "优先级", "rank", "order"))
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def rule_state_of(rule: Any) -> str:
    value = _attr(rule, ("state", "status", "方案状态", "规则状态", "effective_state"))
    return str(value or "生效中")


def parse_datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("/", "-")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def is_rule_effective(rule: Any, at_time: datetime | None = None,
                      signoff: "RuleSignOff | None" = None) -> tuple[bool, str]:
    """核对规则状态和生效期；返回是否生效及原因。"""
    at_time = at_time or _now()
    explicit_rule_effective = _attr(rule, ("effective", "is_effective", "active", "is_active"), None)
    if explicit_rule_effective is False or str(explicit_rule_effective).lower() in {"false", "0", "no", "停用", "失效"}:
        return False, "规则被显式标记为不生效"
    if signoff is not None and (
        signoff.effective is False or getattr(signoff, "is_effective", None) is False
    ):
        return False, "签认被显式标记为不生效"
    state = rule_state_of(rule)
    if state in REVOKED_STATES or str(_attr(rule, ("revoked", "withdrawn", "is_revoked"), False)).lower() == "true":
        return False, f"规则当前状态为{state}，已撤下/失效"
    if state and state not in ACTIVE_RULE_STATES and state not in SIGNED_STATES:
        # 草稿、解析异常等状态不能作为正式签认规则。
        return False, f"规则状态「{state}」不在合法生效状态"

    from_names = ("effective_from", "valid_from", "start_at", "effective_start",
                  "start_date", "生效时间", "生效日期")
    to_names = ("effective_to", "valid_to", "end_at", "effective_end",
                "end_date", "expire_at", "失效时间", "失效日期")
    effective_from = parse_datetime(
        _attr(signoff, from_names, None) if signoff is not None else None
        or _attr(rule, from_names, None)
    )
    effective_to = parse_datetime(
        _attr(signoff, to_names, None) if signoff is not None else None
        or _attr(rule, to_names, None)
    )
    if effective_from and at_time < effective_from:
        return False, "规则尚未进入生效期"
    if effective_to and at_time > effective_to:
        return False, "规则已超过生效期"
    if signoff is not None:
        if not signoff.approved or signoff.status not in SIGNED_STATES | {"active", "effective"}:
            return False, f"规则签认状态为{signoff.status}，不能用于正式分类"
        if signoff.effective_from and parse_datetime(signoff.effective_from) and at_time < parse_datetime(signoff.effective_from):
            return False, "签认尚未生效"
        if signoff.effective_to and parse_datetime(signoff.effective_to) and at_time > parse_datetime(signoff.effective_to):
            return False, "签认已过期"
    return True, "规则处于合法生效期"


def classify_fields(fields: dict[str, Any], event_types: dict[str, EventTypeDef] | None = None,
                    explicit: Any = None, responsibility: str = "") -> EventTypeDef:
    """按显式分类/责任范围或解析字段推断事件类型。"""
    types = event_types or DEFAULT_EVENT_TYPES

    if isinstance(explicit, EventTypeDef):
        return explicit
    explicit_id = _attr(explicit, ("type_id", "id", "event_type_id"), None)
    explicit_tag = _attr(explicit, ("category_tag", "category", "tag"), None)
    explicit_name = _attr(explicit, ("type_name", "name"), None)
    unknown_explicit = ""
    for candidate in (explicit_id, explicit_tag, explicit_name, explicit if isinstance(explicit, str) else None,
                      responsibility):
        if candidate in (None, ""):
            continue
        text = str(candidate)
        unknown_explicit = text
        low = text.strip().lower()
        if low in types:
            return types[low]
        for event_type in types.values():
            if text in (event_type.type_id, event_type.type_name, event_type.category_tag):
                return event_type
        if any(word in text.upper() for word in ("ERROR", "FAULT", "故障", "错误")) or "error" in low:
            return types["error"]
        if any(word in text.upper() for word in _AUTH_WORDS) or any(word in text for word in ("登录", "登陆", "认证", "审计")):
            return types["auth"]
        if "访问" in text or "access" in low:
            return types["access"]

    values = {str(k).lower(): str(v or "").strip() for k, v in (fields or {}).items()}
    level = values.get("level") or values.get("severity") or values.get("log_level") or ""
    if level.upper() in _ERROR_WORDS:
        return types["error"]
    action = values.get("action") or values.get("event") or values.get("operation") or ""
    if action.upper() in _AUTH_WORDS:
        return types["auth"]
    if unknown_explicit:
        key = unknown_explicit.strip()
        type_id = key if key.startswith("EVEN-") else f"CUSTOM-{_short_hash(key, 10)}"
        return EventTypeDef(type_id=type_id, type_name=key, category_tag=key.lower())
    return types["access"]


def event_identity(event_type: EventTypeDef | None) -> str:
    if event_type is None:
        return "unknown"
    return event_type.type_id or event_type.category_tag or event_type.type_name


def event_fingerprint(line_key: str, raw_line: str, event_type: EventTypeDef | None,
                      fields: dict[str, Any]) -> str:
    normalized_fields = {str(k): str(v) for k, v in sorted((fields or {}).items())}
    raw = "\x1f".join([
        line_key or "", raw_line or "", event_identity(event_type),
        hashlib.sha256(repr(normalized_fields).encode("utf-8")).hexdigest(),
    ])
    return _short_hash(raw, 32)


# ---------------------------------------------------------------------------
# 数据记录
# ---------------------------------------------------------------------------

class ReportDict(dict):
    """字典批次报告，同时允许 ``report.rule_results`` 风格访问。"""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __await__(self):
        # 允许同步入口在 async 测试中直接被 await；同步调用本身不受影响。
        yield
        return self


class ClassificationResultList(list):
    """classify_events 的列表返回值，同时携带争议/未命中汇总。"""

    def __init__(self, records: Iterable[EventRecord] = (), **metadata: Any) -> None:
        super().__init__(records)
        self.metadata = metadata
        self.batch = metadata.get("batch")
        self.disputes = metadata.get("disputes", [])
        self.dispute_records = self.disputes
        self.conflicts = self.disputes
        self.classification_disputes = self.disputes
        self.unmatched = metadata.get("unmatched", [])
        self.unmatched_lines = self.unmatched
        self.official_classifications = metadata.get("officials", [])
        self.formal_classifications = self.official_classifications
        self.officials = self.official_classifications
        self.confirmation_records = metadata.get("confirmations", [])
        self.summary = metadata.get("summary", {})

    def __await__(self):
        yield
        return self


class KeyedRegistry(dict):
    """既支持 ``by_key`` 幂等查找，也支持列表式遍历/下标的正式清单。"""

    def __iter__(self):
        return iter(self.values())

    def __getitem__(self, key):
        if isinstance(key, int) and not any(isinstance(k, int) and k == key for k in self.keys()):
            return list(self.values())[key]
        return super().__getitem__(key)

    def all(self) -> list[Any]:
        return list(self.values())

    @property
    def records(self) -> list[Any]:
        return list(self.values())


class FlexibleRecord:
    """同时支持属性、字典键和 ``get`` 访问，降低不同测试构造风格的适配成本。"""

    def __init__(self, **data: Any) -> None:
        self.__dict__.update(data)

    def __getitem__(self, key: str) -> Any:
        return self.__dict__[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.__dict__[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.__dict__.get(key, default)

    def __getattr__(self, name: str) -> Any:
        # 未显式声明的构造参数保存在 metadata 中，也允许按属性直接读取。
        metadata = self.__dict__.get("metadata")
        if isinstance(metadata, dict) and name in metadata:
            return metadata[name]
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if key.startswith("_"):
                continue
            if isinstance(value, FlexibleRecord):
                result[key] = value.to_dict()
            elif isinstance(value, EventTypeDef):
                result[key] = value.type_id
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, list):
                result[key] = [v.to_dict() if isinstance(v, FlexibleRecord) else v for v in value]
            elif isinstance(value, dict):
                result[key] = value
            else:
                result[key] = value
        return result


class RuleSignOff(FlexibleRecord):
    """负责人/责任组对某条规则的签认。"""

    def __init__(self, rule: Any = None, owner_group: str | None = None,
                 responsibility: str | None = None, event_type: Any = None, **kwargs: Any) -> None:
        rule_id = kwargs.pop("rule_id", None) or rule_id_of(rule)
        final_authority = kwargs.pop("final_authority", None)
        if final_authority is None:
            final_authority = kwargs.pop("has_final_authority", None)
        if final_authority is None:
            final_authority = kwargs.pop("is_final_authority", None)
        authority = kwargs.pop("authority", None)
        if isinstance(authority, bool) and final_authority is None:
            final_authority = authority
        explicit_effective = kwargs.pop("effective", None)
        if explicit_effective is None:
            explicit_effective = kwargs.pop("is_effective", None)
        if explicit_effective is None:
            explicit_effective = kwargs.pop("active", None)
        super().__init__(
            rule=rule,
            rule_id=str(rule_id),
            owner_group=owner_group or kwargs.pop("team", None) or kwargs.pop("owner", None)
            or kwargs.pop("responsible_group", None) or kwargs.pop("reviewer_group", None) or "",
            owner=kwargs.get("owner_name", "") or kwargs.pop("reviewer", "") or "",
            responsibility_scope=responsibility or kwargs.pop("scope", None)
            or kwargs.pop("responsible_scope", None) or kwargs.pop("responsibility_scope", None) or "",
            event_type=event_type if not isinstance(event_type, str) else event_type,
            classification=kwargs.pop("classification", None) or (event_type if isinstance(event_type, str) else None),
            category_tag=kwargs.pop("category_tag", None),
            type_id=kwargs.pop("type_id", None),
            priority=kwargs.pop("priority", None),
            final_authority=bool(final_authority) if final_authority is not None else None,
            authority=authority,
            status=kwargs.pop("status", "已签认"),
            approved=kwargs.pop("approved", True),
            signed=kwargs.pop("signed", True),
            effective=explicit_effective,
            is_effective=explicit_effective,
            effective_from=kwargs.pop("effective_from", None) or kwargs.pop("valid_from", None),
            effective_to=kwargs.pop("effective_to", None) or kwargs.pop("valid_to", None),
            signoff_id=kwargs.pop("signoff_id", None) or f"SIGN-{_short_hash(str(rule_id) + str(_now().timestamp()), 10)}",
            signed_at=kwargs.pop("signed_at", _now()),
            note=kwargs.pop("note", ""),
            metadata=kwargs,
        )

    @property
    def scope(self) -> str:
        return self.responsibility_scope

    @property
    def responsible_scope(self) -> str:
        return self.responsibility_scope

    @property
    def is_final_authority(self) -> bool | None:
        return self.final_authority


RuleConfirmation = RuleSignOff
SignOff = RuleSignOff
Signoff = RuleSignOff
RuleApproval = RuleSignOff


class RuleMatchResult(FlexibleRecord):
    """一条规则对一条原行的核对结果。"""

    def __init__(self, line_key: str, raw_line: str, rule_id: str,
                 registered_order: int = 0, **kwargs: Any) -> None:
        parse_status = kwargs.pop("parse_status", "unmatched")
        matched = bool(kwargs.pop("matched", parse_status == "ok"))
        fields = dict(kwargs.pop("fields", {}) or {})
        super().__init__(
            line_key=line_key,
            raw_line=raw_line,
            rule_id=rule_id,
            registered_order=registered_order,
            matched=matched,
            success=matched,
            parse_success=matched,
            parse_status=parse_status,
            status=kwargs.pop("status", "matched" if matched else "unmatched"),
            fields=fields,
            parsed_fields=fields,
            effective_fields=fields,
            reason=kwargs.pop("reason", "" if matched else "未匹配：正则未命中"),
            reason_code=kwargs.pop("reason_code", "" if matched else "regex_mismatch"),
            eligible=kwargs.pop("eligible", matched),
            effective=kwargs.pop("effective", matched),
            signed=kwargs.pop("signed", False),
            signoff_id=kwargs.pop("signoff_id", None),
            priority=kwargs.pop("priority", 100),
            rule_version=kwargs.pop("rule_version", 1),
            owner_group=kwargs.pop("owner_group", ""),
            responsibility_scope=kwargs.pop("responsibility_scope", ""),
            event_type=kwargs.pop("event_type", None),
            event_type_id=kwargs.pop("event_type_id", None),
            category_tag=kwargs.pop("category_tag", None),
            final_authority=kwargs.pop("final_authority", None),
            captured_at=kwargs.pop("captured_at", _now()),
            metadata=kwargs.pop("metadata", {}),
        )
        # 常见测试/调用命名别名，全部指向同一份事实数据。
        self.captured_fields = fields
        self.field_values = fields
        self.rule_fields = fields
        self.captured = dict(fields)
        self.is_match = matched
        self.is_matched = matched
        self.ok = matched
        self.failure_reason = self.reason
        self.unmatched_reason = self.reason
        self.message = self.reason

    @property
    def field_capture(self) -> dict[str, str]:
        return dict(self.fields)

    @property
    def effective_field_values(self) -> dict[str, str]:
        return dict(self.fields)

    def is_usable(self, require_signoff: bool = False) -> bool:
        if not self.matched or not self.eligible or not self.effective:
            return False
        if require_signoff and not self.signed:
            return False
        return True


ParseRuleResult = RuleMatchResult
MatchResult = RuleMatchResult


class ClassificationDecision(FlexibleRecord):
    def __init__(self, result: RuleMatchResult, event_type: EventTypeDef, **kwargs: Any) -> None:
        super().__init__(
            rule_id=result.rule_id,
            line_key=result.line_key,
            event_type=event_type,
            event_type_id=event_identity(event_type),
            category_tag=event_type.category_tag,
            classification_key=event_identity(event_type),
            fields=dict(result.fields),
            original_fields=dict(result.fields),
            priority=kwargs.pop("priority", result.priority),
            owner_group=kwargs.pop("owner_group", result.owner_group),
            responsibility_scope=kwargs.pop("responsibility_scope", result.responsibility_scope),
            final_authority=kwargs.pop("final_authority", result.final_authority),
            signoff_id=result.signoff_id,
            rule_version=result.rule_version,
            registered_order=result.registered_order,
        )


class ClassificationDispute(FlexibleRecord):
    def __init__(self, line_key: str, raw_line: str,
                 decisions: list[ClassificationDecision], reasons: list[dict[str, Any]] | None = None) -> None:
        self.dispute_id = f"DISP-{_short_hash(line_key, 16)}"
        self.line_key = line_key
        self.raw_line = raw_line
        self.decisions = decisions
        self.rule_decisions = decisions
        self.candidates = decisions
        self.rule_ids = [d.rule_id for d in decisions]
        self.rule_fields = {d.rule_id: dict(d.original_fields) for d in decisions}
        self.original_fields_by_rule = dict(self.rule_fields)
        self.fields_by_rule = dict(self.rule_fields)
        self.conflicting_rule_ids = list(self.rule_ids)
        self.classification_keys = sorted({d.event_type_id for d in decisions})
        self.conflict_keys = list(self.classification_keys)
        self.conflict_fields = self._field_conflicts(decisions)
        self.field_conflicts = self.conflict_fields
        self.conflicting_fields = self.conflict_fields
        self.mutex_fields = self.conflict_fields
        self.reasons = reasons or []
        self.status = "disputed"
        self.classification_status = "disputed"
        self.state = "争议隔离"
        self.isolated = True
        self.created_at = _now()
        self.updated_at = _now()
        self.replay_count = 0
        self.history: list[dict[str, Any]] = []

    @staticmethod
    def _field_conflicts(decisions: list[ClassificationDecision]) -> list[dict[str, Any]]:
        values: dict[str, list[tuple[str, Any]]] = {}
        for decision in decisions:
            for key, value in (decision.fields or {}).items():
                values.setdefault(key, []).append((decision.rule_id, value))
        conflicts = []
        for key, refs in values.items():
            distinct = {str(value) for _, value in refs}
            if len(distinct) > 1:
                conflicts.append({"field": key, "values": refs})
        # 即使 level/action 不是同名字段，分类判断互斥也是核心冲突。
        return conflicts

    def replay(self) -> "ClassificationDispute":
        """按每条规则保留的原始字段重新计算分类冲突。"""
        self.replay_count += 1
        recomputed: list[ClassificationDecision] = []
        for decision in self.decisions:
            event_type = classify_fields(
                decision.original_fields,
                explicit=decision.event_type,
                responsibility=decision.responsibility_scope,
            )
            recomputed.append(ClassificationDecision(
                RuleMatchResult(
                    line_key=self.line_key, raw_line=self.raw_line, rule_id=decision.rule_id,
                    fields=decision.original_fields, priority=decision.priority,
                    owner_group=decision.owner_group,
                    responsibility_scope=decision.responsibility_scope,
                    signoff_id=decision.signoff_id, rule_version=decision.rule_version,
                    registered_order=decision.registered_order,
                    final_authority=decision.final_authority,
                ),
                event_type,
            ))
        self.decisions = recomputed
        self.rule_decisions = recomputed
        self.candidates = recomputed
        self.classification_keys = sorted({d.event_type_id for d in recomputed})
        self.conflict_keys = list(self.classification_keys)
        self.rule_ids = [d.rule_id for d in recomputed]
        self.conflicting_rule_ids = list(self.rule_ids)
        self.updated_at = _now()
        return self


DisputeRecord = ClassificationDispute


class ConfirmationRecord(FlexibleRecord):
    def __init__(self, line_key: str, raw_line: str, result: RuleMatchResult,
                 decision: ClassificationDecision | None = None, batch_id: str = "") -> None:
        self.confirmation_id = "CONF-" + _short_hash(
            f"{line_key}|{result.rule_id}|{result.rule_version}|{sorted(result.fields.items())}|{result.signoff_id}", 18)
        self.batch_id = batch_id
        self.line_key = line_key
        self.raw_line = raw_line
        self.rule_id = result.rule_id
        self.rule_version = result.rule_version
        self.fields = dict(result.fields)
        self.original_fields = dict(result.fields)
        self.event_type_id = decision.event_type_id if decision else result.event_type_id
        self.category_tag = decision.category_tag if decision else result.category_tag
        self.owner_group = result.owner_group
        self.responsibility_scope = result.responsibility_scope
        self.signoff_id = result.signoff_id
        self.priority = result.priority
        self.status = "confirmed"
        self.state = "重复确认"
        self.confirmed_at = _now()


DuplicateConfirmationRecord = ConfirmationRecord
RuleConfirmationRecord = ConfirmationRecord
ConfirmedRuleRecord = ConfirmationRecord


class OfficialClassification(FlexibleRecord):
    def __init__(self, line_key: str, raw_line: str, record: EventRecord,
                 fingerprint: str, rule_ids: list[str], confirmation_ids: list[str],
                 batch_id: str = "", version: int = 1) -> None:
        self.classification_id = "OFFC-" + _short_hash(line_key, 18)
        self.official_id = self.classification_id
        self.formal_id = self.classification_id
        self.line_key = line_key
        self.raw_line = raw_line
        self.original_content = raw_line[:500]
        self.record = record
        self.event_type = record.event_type
        self.event_type_id = event_identity(record.event_type)
        self.category_tag = record.event_type.category_tag
        self.parsed_fields = dict(record.parsed_fields)
        self.fingerprint = fingerprint
        self.content_fingerprint = fingerprint
        self.rule_ids = list(rule_ids)
        self.confirmed_rule_ids = list(rule_ids)
        self.confirmation_ids = list(confirmation_ids)
        self.batch_id = batch_id
        self.version = version
        self.confirmed_version = version
        self.confirmation_version = version
        self.status = "official"
        self.classification_status = "official"
        self.state = "已正式分类"
        self.created_at = _now()
        self.updated_at = _now()
        self.history: list[dict[str, Any]] = []
        # 让正式 EventRecord 本身也携带幂等/版本信息，方便只接触事件对象的调用方。
        for attr_name, attr_value in {
            "line_key": line_key,
            "classification_id": self.classification_id,
            "official_classification_id": self.classification_id,
            "confirmed_version": version,
            "confirmation_version": version,
            "classification_status": "official",
        }.items():
            try:
                setattr(self.record, attr_name, attr_value)
            except Exception:
                pass

    @property
    def record_id(self) -> str:
        return self.record.record_id

    @property
    def masked_fields(self) -> dict[str, str]:
        return self.record.masked_fields

    @property
    def enriched_fields(self) -> dict[str, str]:
        return self.record.enriched_fields

    @property
    def event_time(self) -> datetime:
        return self.record.event_time

    @property
    def source_host(self) -> str:
        return self.record.source_host

    @property
    def store_partition(self) -> str:
        return self.record.store_partition

    @property
    def index_state(self) -> str:
        return self.record.index_state

    @index_state.setter
    def index_state(self, value: str) -> None:
        self.record.index_state = value

    def bump_version(self, new_record: EventRecord, new_fingerprint: str,
                     rule_ids: list[str], confirmation_ids: list[str]) -> bool:
        changed = new_fingerprint != self.fingerprint
        if changed:
            old_snapshot = {
                "version": self.version,
                "fingerprint": self.fingerprint,
                "event_type_id": self.event_type_id,
                "parsed_fields": dict(self.parsed_fields),
                "at": _now().isoformat(),
            }
            self.history.append(old_snapshot)
        # 直接变更同一个 EventRecord，避免事件仓库中留下旧分类对象和重复行。
        self.record.event_type = new_record.event_type
        self.record.parsed_fields = dict(new_record.parsed_fields)
        self.record.event_time = new_record.event_time
        self.record.source_host = new_record.source_host
        self.record.store_partition = new_record.store_partition
        self.fingerprint = new_fingerprint
        self.content_fingerprint = new_fingerprint
        self.event_type = self.record.event_type
        self.event_type_id = event_identity(self.record.event_type)
        self.category_tag = self.record.event_type.category_tag
        self.parsed_fields = dict(self.record.parsed_fields)
        self.rule_ids = list(rule_ids)
        self.confirmed_rule_ids = list(rule_ids)
        self.confirmation_ids = list(confirmation_ids)
        if changed:
            self.version += 1
            self.confirmed_version = self.version
            self.confirmation_version = self.version
            self.updated_at = _now()
        for attr_name in ("confirmed_version", "confirmation_version"):
            try:
                setattr(self.record, attr_name, getattr(self, attr_name))
            except Exception:
                pass
        try:
            self.record.classification_status = self.status
        except Exception:
            pass
        return changed


OfficialRecord = OfficialClassification
FormalClassification = OfficialClassification
# 对外它可以按 EventRecord 做类型判断；实际存储同时保留版本/签认元数据。
EventRecord.register(OfficialClassification)


# ---------------------------------------------------------------------------
# 双匹配批次
# ---------------------------------------------------------------------------

@dataclass
class _NormLine:
    line_key: str
    raw_line: str
    line_number: int
    source_id: str


class DualMatchBatch:
    """同一来源、同一批原行对多条解析规则的核验/签认/分类批次。"""

    def __init__(self, entries: Any = None, rules: Iterable[Any] | None = None,
                 *, signoffs: Iterable[RuleSignOff | dict[str, Any]] | None = None,
                 source_id: str = "", batch_id: str | None = None,
                 event_types: dict[str, EventTypeDef] | None = None,
                 require_signoff: bool | None = None,
                 record_factory: Callable[..., EventRecord] | None = None,
                 auto_run: bool = False, **metadata: Any) -> None:
        self.batch_id = batch_id or f"DMB-{_short_hash(repr((str(entries), str(rules), _now().timestamp())), 16)}"
        self.source_id = source_id
        self.event_types = event_types or DEFAULT_EVENT_TYPES
        self.record_factory = record_factory
        self.require_signoff = require_signoff
        self.metadata = metadata
        self.created_at = _now()

        self.rules: list[Any] = []
        self.rule_order: dict[str, int] = {}
        self.signoffs: dict[str, RuleSignOff] = {}
        self.signoff_history: dict[str, list[RuleSignOff]] = {}

        self.lines: list[_NormLine] = []
        self.line_reports: dict[str, dict[str, Any]] = {}
        self.rule_results: list[RuleMatchResult] = []
        self.results_by_line: dict[str, list[RuleMatchResult]] = {}
        self.results_by_rule: dict[str, list[RuleMatchResult]] = {}
        self.rule_line_hits: dict[str, set[str]] = {}
        self.rule_revisions: dict[str, list[dict[str, Any]]] = {}
        self.rule_rerun_keys: dict[str, list[str]] = {}

        self.official_classifications: KeyedRegistry = KeyedRegistry()
        self.officials = self.official_classifications
        self.inactive_official_classifications: KeyedRegistry = KeyedRegistry()
        self.retired_officials: list[OfficialClassification] = []
        self.official_records: list[EventRecord] = []
        self.disputes: KeyedRegistry = KeyedRegistry()
        self.conflicts = self.disputes
        self.resolved_disputes: KeyedRegistry = KeyedRegistry()
        self.dispute_history: list[ClassificationDispute] = []
        self.disputed_records: list[ClassificationDispute] = []
        self.confirmation_records: list[ConfirmationRecord] = []
        self._confirmation_keys: set[str] = set()
        self.submission_receipts: list[dict[str, Any]] = []
        self.unmatched_lines: list[dict[str, Any]] = []
        self.line_ledger: dict[str, dict[str, Any]] = {}

        self._lock = threading.RLock()
        self._key_locks: dict[str, threading.RLock] = {}
        self._key_locks_guard = threading.Lock()

        if rules is not None:
            self.register_rules(rules)
        if signoffs is not None:
            for item in signoffs:
                if isinstance(item, RuleSignOff):
                    self.add_signoff(item)
                elif isinstance(item, dict):
                    self.sign_rule(**item)
        if entries is not None:
            self.set_entries(entries)
        if auto_run and entries is not None:
            self.run()

    # ---------- 输入和规则 ----------

    def register_rules(self, rules: Iterable[Any] | Any) -> "DualMatchBatch":
        if rules is None:
            return self
        if not isinstance(rules, (list, tuple, set)) or hasattr(rules, "raw_line"):
            rules = [rules]
        for index, rule in enumerate(rules):
            self.register_rule(rule, order=index)
        return self

    def register_rule(self, rule: Any, order: int | None = None) -> "DualMatchBatch":
        rule_id = rule_id_of(rule)
        if rule not in self.rules:
            self.rules.append(rule)
        if order is None:
            order = len(self.rule_order)
        self.rule_order[rule_id] = int(order)
        self.rule_line_hits.setdefault(rule_id, set())
        return self

    add_rule = register_rule

    def set_entries(self, entries: Any) -> "DualMatchBatch":
        normalized = self._normalize_entries(entries)
        self.lines = normalized
        for line in normalized:
            self.line_reports.setdefault(line.line_key, ReportDict({
                "line_key": line.line_key,
                "raw_line": line.raw_line,
                "source_id": line.source_id,
                "line_number": line.line_number,
            }))
            self.line_ledger.setdefault(line.line_key, {
                "line_key": line.line_key,
                "raw_line": line.raw_line,
                "status": "pending",
                "reasons": [],
                "official_id": None,
                "dispute_id": None,
                "attempts": 0,
            })
        return self

    def _normalize_entries(self, entries: Any) -> list[_NormLine]:
        if entries is None:
            return []
        if isinstance(entries, (str, bytes)) or hasattr(entries, "raw_line") or isinstance(entries, dict):
            entries = [entries]
        result: list[_NormLine] = []
        for index, entry in enumerate(entries, start=1):
            if isinstance(entry, bytes):
                raw = entry.decode("utf-8", "replace")
                explicit = None
                line_number = index
                source_id = self.source_id
            elif isinstance(entry, str):
                raw = entry
                explicit = None
                line_number = index
                source_id = self.source_id
            elif isinstance(entry, dict):
                raw = str(_attr(entry, ("raw_line", "original_content", "line", "content", "原行", "原始内容"), ""))
                explicit = _attr(entry, ("line_key", "key", "line_id", "id", "原行编号"))
                line_number = int(_attr(entry, ("line_number", "line_no", "lineno"), index) or index)
                source_id = str(_attr(entry, ("source_id", "来源编号", "source"), self.source_id) or self.source_id)
            else:
                raw = str(_attr(entry, ("raw_line", "original_content", "line", "content"), ""))
                explicit = _attr(entry, ("line_key", "key", "line_id"), None)
                line_number = int(_attr(entry, ("line_number", "line_no", "lineno"), index) or index)
                source_id = str(_attr(entry, ("source_id",), self.source_id) or self.source_id)
            if not raw:
                continue
            key = _stable_line_key(source_id, line_number, raw, str(explicit) if explicit else None)
            result.append(_NormLine(key, raw, line_number, source_id))
        return result

    # ---------- 签认 ----------

    def sign_rule(self, rule: Any = None, owner_group: str | None = None,
                  responsibility: str | None = None, event_type: Any = None, **kwargs: Any) -> RuleSignOff:
        if rule is not None:
            self.register_rule(rule)
        signoff = RuleSignOff(rule=rule, owner_group=owner_group, responsibility=responsibility,
                              event_type=event_type, **kwargs)
        rule_id = signoff.rule_id
        self.signoffs[rule_id] = signoff
        self.signoff_history.setdefault(rule_id, []).append(signoff)
        if self.require_signoff is None:
            # 调用方一旦显式登记签认，本批次默认按签认结果复查。
            self.require_signoff = True
        return signoff

    confirm_rule = sign_rule
    approve_rule = sign_rule
    signoff_rule = sign_rule
    confirm = sign_rule
    sign = sign_rule
    approve = sign_rule

    def add_signoff(self, signoff: RuleSignOff) -> RuleSignOff:
        self.signoffs[signoff.rule_id] = signoff
        self.signoff_history.setdefault(signoff.rule_id, []).append(signoff)
        if self.require_signoff is None:
            self.require_signoff = True
        # 签认可能发生在解析之后；同步已有捕获结果，使“重试按实际签认复查”生效。
        rule_obj = next((rule for rule in self.rules if rule_id_of(rule) == signoff.rule_id), None)
        effective, _reason = is_rule_effective(rule_obj, signoff=signoff)
        for result in self.results_by_rule.get(signoff.rule_id, []):
            result.signed = True
            result.signoff_id = signoff.signoff_id
            result.owner_group = signoff.owner_group or result.owner_group
            result.responsibility_scope = signoff.responsibility_scope or result.responsibility_scope
            if signoff.priority is not None:
                result.priority = signoff.priority
            if signoff.final_authority is not None:
                result.final_authority = signoff.final_authority
            if signoff.event_type is not None:
                result.event_type = signoff.event_type
            if signoff.type_id:
                result.event_type_id = signoff.type_id
            if signoff.category_tag:
                result.category_tag = signoff.category_tag
            result.effective = effective
            result.eligible = bool(result.matched and effective)
        return signoff

    # ---------- 双匹配执行 ----------

    def run(self, rules: Iterable[Any] | Any | None = None) -> "DualMatchBatch":
        if rules is not None:
            self.register_rules(rules)
        with self._lock:
            for line in self.lines:
                self._run_line(line)
            self._refresh_line_summaries()
        return self

    verify = run
    check = run
    apply = run

    def _run_line(self, line: _NormLine, rule_ids: list[str] | None = None) -> list[RuleMatchResult]:
        output: list[RuleMatchResult] = []
        selected_rules = self.rules if rule_ids is None else [
            rule for rule in self.rules if rule_id_of(rule) in set(rule_ids)
        ]
        for rule in selected_rules:
            result = self._run_rule(line, rule)
            output.append(result)
            self.rule_results.append(result)
            self.results_by_line.setdefault(line.line_key, []).append(result)
            self.results_by_rule.setdefault(result.rule_id, []).append(result)
            if result.matched:
                self.rule_line_hits.setdefault(result.rule_id, set()).add(line.line_key)
        return output

    def _run_rule(self, line: _NormLine, rule: Any) -> RuleMatchResult:
        rid = rule_id_of(rule)
        order = self.rule_order.get(rid, 100)
        priority = rule_priority_of(rule)
        signoff = self.signoffs.get(rid)
        effective, effective_reason = is_rule_effective(rule, signoff=signoff)
        fields: dict[str, Any] = {}
        matched = False
        status = "unmatched"
        reason = "未匹配：正则未命中"
        reason_code = "regex_mismatch"

        parse_method = getattr(rule, "parse", None)
        if callable(parse_method):
            try:
                parsed_status, parsed_fields = parse_method(line.raw_line)
                status_value = getattr(parsed_status, "value", str(parsed_status))
                status = str(status_value)
                fields = dict(parsed_fields or {})
                matched = status == "ok"
                if matched:
                    reason = ""
                    reason_code = ""
                elif status == "field_missing":
                    reason = "未完全匹配：解析字段缺失（field_missing）"
                    reason_code = "field_missing"
                else:
                    reason = f"未匹配：{effective_reason if not effective else '正则未命中'}（{status}）"
                    reason_code = status
            except Exception as exc:  # 解析规则自身错误也要成为可查原因，不能静默跳过。
                matched = False
                status = "parse_error"
                reason_code = "parse_error"
                reason = f"未匹配：规则执行异常：{type(exc).__name__}: {exc}"
        else:
            pattern = rule_pattern_of(rule)
            field_names = rule_field_names_of(rule)
            try:
                if hasattr(pattern, "match"):
                    match = pattern.match(line.raw_line.strip())
                else:
                    match = re.compile(str(pattern)).match(line.raw_line.strip()) if pattern else None
                if match is None:
                    matched = False
                    status = "format_mismatch"
                else:
                    groups = match.groups()
                    fields = dict(zip(field_names, groups))
                    if len(field_names) != len(groups) or any(name not in fields for name in field_names):
                        status = "field_missing"
                        reason = "未完全匹配：解析字段缺失（field_missing）"
                        reason_code = "field_missing"
                    else:
                        matched = True
                        status = "ok"
                        reason = ""
                        reason_code = ""
            except re.error as exc:
                status = "invalid_regex"
                reason_code = "invalid_regex"
                reason = f"未匹配：正则表达式非法：{exc}"

        signed = signoff is not None and bool(signoff.approved) and signoff.status in SIGNED_STATES
        if matched and not effective:
            reason = effective_reason
            reason_code = "rule_not_effective"
        result = RuleMatchResult(
            line_key=line.line_key,
            raw_line=line.raw_line,
            rule_id=rid,
            registered_order=order,
            matched=matched,
            parse_status=status,
            fields=fields if matched else {},
            reason=reason,
            reason_code=reason_code,
            eligible=matched and effective and (not self.require_signoff or signed),
            effective=effective,
            signed=signed,
            signoff_id=signoff.signoff_id if signoff else None,
            priority=signoff.priority if signoff and signoff.priority is not None else priority,
            rule_version=int(_attr(rule, ("version", "revision", "规则版本"), 1) or 1),
            owner_group=signoff.owner_group if signoff else str(_attr(
                rule, ("owner_group", "responsible_group", "team", "owner", "group"), "") or ""),
            responsibility_scope=(signoff.responsibility_scope if signoff else
                                  str(_attr(rule, ("responsibility", "scope", "responsible_for",
                                                   "responsible_scope", "responsibility_scope", "domain"), "") or "")),
            event_type=signoff.event_type if signoff else _attr(rule, ("event_type", "classification"), None),
            event_type_id=signoff.type_id if signoff else _attr(rule, ("event_type_id",), None),
            category_tag=signoff.category_tag if signoff else _attr(rule, ("category_tag",), None),
            final_authority=signoff.final_authority if signoff and signoff.final_authority is not None else _attr(rule, ("final_authority", "has_final_authority"), None),
        )
        return result

    def _latest_results_by_rule(self, line_key: str) -> list[RuleMatchResult]:
        latest: dict[str, RuleMatchResult] = {}
        for result in self.results_by_line.get(line_key, []):
            # 结果按执行时间追加；同规则后追加的修订捕获即最新版本。
            latest[result.rule_id] = result
        return list(latest.values())

    def _is_currently_usable(self, result: RuleMatchResult, at_time: datetime | None = None) -> bool:
        """复查规则当前状态/生效期/签认，而不是只信任首次运行时的快照。"""
        rule = next((item for item in self.rules if rule_id_of(item) == result.rule_id), None)
        signoff = self.signoffs.get(result.rule_id)
        effective, reason = is_rule_effective(rule, at_time=at_time, signoff=signoff)
        signed = bool(signoff and signoff.approved and signoff.status in SIGNED_STATES)
        require = bool(self.require_signoff)
        usable = bool(result.matched and effective and (not require or signed))
        result.effective = effective
        result.signed = signed
        result.eligible = usable
        result.current_effective_reason = reason
        if signoff is not None:
            result.signoff_id = signoff.signoff_id
        return usable

    def _usable_results(self, line_key: str, at_time: datetime | None = None) -> list[RuleMatchResult]:
        # 规则修订会追加新版本结果；正式分类只看每条规则的最新捕获，旧值仅留痕查询。
        results = [r for r in self._latest_results_by_rule(line_key)
                   if self._is_currently_usable(r, at_time=at_time)]
        return sorted(results, key=lambda r: (r.priority, r.registered_order, r.rule_id))

    def _all_successful_results(self, line_key: str) -> list[RuleMatchResult]:
        results = [r for r in self._latest_results_by_rule(line_key) if r.matched]
        return sorted(results, key=lambda r: (r.priority, r.registered_order, r.rule_id))

    def _decision_for(self, result: RuleMatchResult) -> ClassificationDecision:
        direct_explicit = result.event_type_id or result.event_type or result.category_tag
        values = {str(k).lower(): str(v or "").upper() for k, v in (result.fields or {}).items()}
        has_classification_field = any(
            key in values for key in ("level", "severity", "log_level", "action", "event", "operation")
        )
        if direct_explicit:
            event_type = classify_fields(result.fields, self.event_types, explicit=direct_explicit)
        elif has_classification_field:
            # 规则修订后必须按“新捕获结果”重新分类，因此字段信号优先于旧责任范围。
            event_type = classify_fields(result.fields, self.event_types)
        else:
            event_type = classify_fields(
                result.fields, self.event_types, responsibility=result.responsibility_scope,
            )
        return ClassificationDecision(result, event_type)

    def _refresh_line_summaries(self) -> None:
        self.unmatched_lines.clear()
        for line in self.lines:
            key = line.line_key
            results = self.results_by_line.get(key, [])
            successes = [r for r in results if r.matched]
            reasons = [
                {"rule_id": r.rule_id, "reason": r.reason, "status": r.status,
                 "effective": r.effective, "signed": r.signed}
                for r in results if not r.matched or not r.eligible
            ]
            report = self.line_reports[key]
            report.update({
                "rule_results": results,
                "successful_results": successes,
                "effective_fields": {r.rule_id: dict(r.fields) for r in successes},
                "reasons": reasons,
            })
            ledger = self.line_ledger[key]
            ledger["reasons"] = reasons
            if not successes:
                ledger["status"] = "unmatched"
                if not any(item["line_key"] == key for item in self.unmatched_lines):
                    self.unmatched_lines.append({"line_key": key, "raw_line": line.raw_line, "reasons": reasons})

    # ---------- 查询入口 ----------

    def _resolve_line_key(self, line: Any) -> str | None:
        if isinstance(line, str):
            if line in self.line_reports:
                return line
            matches = [item.line_key for item in self.lines if item.raw_line == line]
            return matches[0] if matches else None
        if isinstance(line, int):
            # 业务调用更常传 1-based 行号；先按 line_number 精确匹配。
            for candidate in self.lines:
                if candidate.line_number == line:
                    return candidate.line_key
            if 0 <= line < len(self.lines):
                return self.lines[line].line_key
            return None
        key = _attr(line, ("line_key", "key", "line_key"), None)
        if key and key in self.line_reports:
            return str(key)
        raw = _attr(line, ("raw_line", "original_content"), None)
        if raw is not None:
            return self._resolve_line_key(str(raw))
        return None

    def get_results(self, line: Any = None, rule_id: str | None = None) -> list[RuleMatchResult]:
        if line is None:
            results = list(self.rule_results)
        else:
            key = self._resolve_line_key(line)
            results = list(self.results_by_line.get(key or "", [])) if key else []
        if rule_id is not None:
            results = [r for r in results if r.rule_id == rule_id]
        return results

    def get_rule_fields(self, line: Any, rule_id: str | None = None,
                        *, include_history: bool = True) -> dict[str, Any] | list[RuleMatchResult] | None:
        """负责人查询两条规则对同一原行给出的有效字段。

        指定 ``rule_id`` 时返回字段字典；不指定时返回 ``{rule_id: fields}``。
        """
        key = self._resolve_line_key(line)
        if key is None:
            return None if rule_id else {}
        results = self.results_by_line.get(key, [])
        if rule_id:
            matching = [r for r in results if r.rule_id == rule_id and r.matched]
            if not matching and include_history:
                matching = [r for r in results if r.rule_id == rule_id]
            return dict(matching[-1].fields) if matching else {}
        return {r.rule_id: dict(r.fields) for r in results if r.matched or include_history}

    def fields_by_rule(self, line: Any) -> dict[str, dict[str, Any]]:
        key = self._resolve_line_key(line)
        return {r.rule_id: dict(r.fields) for r in self.results_by_line.get(key or "", [])}

    def unmatched_reasons(self, line: Any = None) -> Any:
        if line is None:
            return list(self.unmatched_lines)
        key = self._resolve_line_key(line)
        return [r.reason for r in self.results_by_line.get(key or "", []) if r.reason]

    get_unmatched_reasons = unmatched_reasons

    def get_dispute(self, line: Any) -> ClassificationDispute | None:
        key = self._resolve_line_key(line)
        return self.disputes.get(key or "")

    def get_official(self, line: Any) -> OfficialClassification | None:
        key = self._resolve_line_key(line)
        return self.official_classifications.get(key or "")

    def list_official(self) -> list[OfficialClassification]:
        return list(self.official_classifications.values())

    get_official_classifications = list_official
    get_formal_classifications = list_official

    def list_disputes(self) -> list[ClassificationDispute]:
        return list(self.disputes.values())

    get_disputes = list_disputes

    def get_confirmation_records(self, line: Any = None) -> list[ConfirmationRecord]:
        if line is None:
            return list(self.confirmation_records)
        key = self._resolve_line_key(line)
        return [item for item in self.confirmation_records if item.line_key == key]

    confirmations = property(lambda self: list(self.confirmation_records))

    # ---------- 分类和幂等提交 ----------

    def _deactivate_official(self, key: str, status: str, state: str) -> OfficialClassification | None:
        official = self.official_classifications.pop(key, None)
        if official is None:
            return self.inactive_official_classifications.get(key)
        official.status = status
        official.classification_status = status
        official.state = state
        self.inactive_official_classifications[key] = official
        if official not in self.retired_officials:
            self.retired_officials.append(official)
        return official

    def evaluate(self, selected_keys: Iterable[str] | None = None,
                 at_time: datetime | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if not self.line_reports:
                self._refresh_line_summaries()
            keys = list(selected_keys) if selected_keys is not None else [line.line_key for line in self.lines]
            plans: list[dict[str, Any]] = []
            for key in keys:
                ledger = self.line_ledger.setdefault(key, {"attempts": 0})
                ledger["attempts"] = int(ledger.get("attempts", 0)) + 1
                usable = self._usable_results(key, at_time=at_time)
                if not usable:
                    all_success = self._all_successful_results(key)
                    had_official = key in self.official_classifications
                    if all_success and self.require_signoff:
                        reasons = [{"rule_id": r.rule_id, "reason": "成功解析但缺少有效签认/生效条件",
                                    "status": "signoff_required"} for r in all_success]
                    else:
                        reasons = self.line_reports.get(key, {}).get("reasons", [])
                    if all_success or had_official:
                        self._deactivate_official(key, "inactive", "规则已失效或不再命中")
                        ledger.update({"status": "inactive", "reasons": reasons, "official_id": None})
                    else:
                        ledger.update({"status": "unmatched", "reasons": reasons, "official_id": None})
                    continue

                decisions = [self._decision_for(result) for result in usable]
                distinct = sorted({d.event_type_id for d in decisions})
                if len(distinct) > 1 and not self._has_final_authority(decisions):
                    self._deactivate_official(key, "disputed", "争议隔离")
                    dispute = self._upsert_dispute(key, decisions)
                    ledger.update({"status": "disputed", "dispute_id": dispute.dispute_id,
                                   "official_id": None})
                    continue

                chosen = self._choose_decision(decisions)
                # 同一分类的两份成功在此合并字段，但确认记录仍按规则分别保留。
                merged_fields: dict[str, Any] = {}
                for decision in sorted(decisions, key=lambda d: (d.priority, d.registered_order, d.rule_id)):
                    for field_name, value in decision.fields.items():
                        merged_fields.setdefault(field_name, value)
                raw_line = self.line_reports[key]["raw_line"]
                fingerprint = event_fingerprint(key, raw_line, chosen.event_type, merged_fields)
                plans.append({
                    "line_key": key,
                    "raw_line": raw_line,
                    "decision": chosen,
                    "decisions": decisions,
                    "event_type": chosen.event_type,
                    "fields": merged_fields,
                    "fingerprint": fingerprint,
                })
            return plans

    def _has_final_authority(self, decisions: list[ClassificationDecision]) -> bool:
        authoritative = [d for d in decisions if d.final_authority is True]
        return len({d.event_type_id for d in authoritative}) == 1 and len(authoritative) >= 1

    def _choose_decision(self, decisions: list[ClassificationDecision]) -> ClassificationDecision:
        authoritative = [d for d in decisions if d.final_authority is True]
        if authoritative:
            return sorted(authoritative, key=lambda d: (d.priority, d.registered_order, d.rule_id))[0]
        # 无冲突时选最高优先级仅作为代表；不会用它压制互斥分类。
        return sorted(decisions, key=lambda d: (d.priority, d.registered_order, d.rule_id))[0]

    def _upsert_dispute(self, key: str, decisions: list[ClassificationDecision]) -> ClassificationDispute:
        raw_line = self.line_reports[key]["raw_line"]
        reasons = self.line_reports[key].get("reasons", [])
        existing = self.disputes.get(key)
        if existing is None:
            dispute = ClassificationDispute(key, raw_line, decisions, reasons)
            self.disputes[key] = dispute
            self.disputed_records.append(dispute)
        else:
            old = {"keys": list(existing.classification_keys), "at": existing.updated_at.isoformat()}
            existing.history.append(old)
            existing.decisions = decisions
            existing.rule_decisions = decisions
            existing.candidates = decisions
            existing.rule_ids = [d.rule_id for d in decisions]
            existing.rule_fields = {d.rule_id: dict(d.original_fields) for d in decisions}
            existing.original_fields_by_rule = dict(existing.rule_fields)
            existing.fields_by_rule = dict(existing.rule_fields)
            existing.conflicting_rule_ids = list(existing.rule_ids)
            existing.classification_keys = sorted({d.event_type_id for d in decisions})
            existing.conflict_keys = list(existing.classification_keys)
            existing.conflict_fields = ClassificationDispute._field_conflicts(decisions)
            existing.field_conflicts = existing.conflict_fields
            existing.conflicting_fields = existing.conflict_fields
            existing.mutex_fields = existing.conflict_fields
            existing.updated_at = _now()
            dispute = existing
        self.line_ledger[key].update({"status": "disputed", "dispute_id": dispute.dispute_id})
        return dispute

    def _key_lock(self, key: str) -> threading.RLock:
        with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._key_locks[key] = lock
            return lock

    def _resolve_dispute_for_key(self, key: str) -> ClassificationDispute | None:
        dispute = self.disputes.pop(key, None)
        if dispute is None:
            return self.resolved_disputes.get(key)
        dispute.status = "resolved"
        dispute.classification_status = "official"
        dispute.state = "已复核解决"
        dispute.resolved_at = _now()
        self.resolved_disputes[key] = dispute
        self.dispute_history.append(dispute)
        return dispute

    def commit_plan(self, plan: dict[str, Any], record: EventRecord | None = None) -> tuple[OfficialClassification, bool]:
        key = plan["line_key"]
        with self._key_lock(key):
            if record is None:
                if self.record_factory is None:
                    record = self._default_record_factory(plan)
                else:
                    record = self.record_factory(plan)
            confirmation_ids = self._record_confirmations(plan)
            self._resolve_dispute_for_key(key)
            existing = self.official_classifications.get(key)
            if existing is not None:
                changed = existing.bump_version(record, plan["fingerprint"],
                                                [d.rule_id for d in plan["decisions"]], confirmation_ids)
                self.submission_receipts.append({
                    "line_key": key, "duplicate": not changed, "changed": changed,
                    "official_id": existing.classification_id, "at": _now().isoformat(),
                })
                self.line_ledger[key].update({
                    "status": "official", "official_id": existing.classification_id, "dispute_id": None,
                })
                if key in self.disputes and not changed:
                    # 已解决的争议在重新分类成功后从当前隔离表移除，但历史仍可通过 history 查询。
                    pass
                return existing, changed

            official = OfficialClassification(
                line_key=key,
                raw_line=plan["raw_line"],
                record=record,
                fingerprint=plan["fingerprint"],
                rule_ids=[d.rule_id for d in plan["decisions"]],
                confirmation_ids=confirmation_ids,
                batch_id=self.batch_id,
            )
            self.official_classifications[key] = official
            self.official_records.append(record)
            self.submission_receipts.append({
                "line_key": key, "duplicate": False, "changed": True,
                "official_id": official.classification_id, "at": _now().isoformat(),
            })
            self.line_ledger[key].update({
                "status": "official", "official_id": official.classification_id, "dispute_id": None,
            })
            return official, True

    submit_official_classification = commit_plan
    commit_official_classification = commit_plan
    save_official_classification = commit_plan
    insert_official_classification = commit_plan

    def _record_confirmations(self, plan: dict[str, Any]) -> list[str]:
        ids: list[str] = []
        key = plan["line_key"]
        for decision in plan["decisions"]:
            matching = [r for r in self.results_by_line.get(key, []) if r.rule_id == decision.rule_id]
            result = matching[-1] if matching else None
            if result is None:
                continue
            confirmation = ConfirmationRecord(key, plan["raw_line"], result, decision, self.batch_id)
            ids.append(confirmation.confirmation_id)
            if confirmation.confirmation_id not in self._confirmation_keys:
                self._confirmation_keys.add(confirmation.confirmation_id)
                self.confirmation_records.append(confirmation)
        return ids

    def classify(self, *, commit: bool = True, at_time: datetime | None = None) -> list[OfficialClassification]:
        plans = self.evaluate(at_time=at_time)
        officials: list[OfficialClassification] = []
        for plan in plans:
            official, _ = self.commit_plan(plan) if commit else (
                self.official_classifications.get(plan["line_key"]) or
                OfficialClassification(plan["line_key"], plan["raw_line"],
                                       self._default_record_factory(plan), plan["fingerprint"], [], []),
                False,
            )
            officials.append(official)
        return officials

    def classify_events(self, entries: Any = None, at_time: datetime | None = None) -> list[EventRecord]:
        selected_keys = None
        if entries is not None:
            normalized = self._normalize_entries(entries)
            selected_keys = [line.line_key for line in normalized]
        plans = self.evaluate(selected_keys, at_time=at_time)
        records: list[EventRecord] = []
        for plan in plans:
            official, _ = self.commit_plan(plan)
            records.append(official.record)
        return records

    def submit(self, entries: Any = None, rules: Any = None, **kwargs: Any) -> dict[str, Any]:
        if entries is not None and not self.lines:
            self.set_entries(entries)
        if rules is not None:
            self.register_rules(rules)
        if not self.rule_results:
            self.run()
        officials = self.classify(**kwargs)
        return {
            "batch_id": self.batch_id,
            "official_count": len(officials),
            "disputed_count": len(self.disputes),
            "unmatched_count": len(self.unmatched_lines),
            "officials": officials,
            "disputes": self.list_disputes(),
            "unmatched": self.unmatched_lines,
            "confirmation_records": self.confirmation_records,
        }

    # ---------- 重试、争议重跑、规则修订 ----------

    def retry(self, *, rerun_rules: bool = False, at_time: datetime | None = None) -> dict[str, Any]:
        """按当前实际签认结果复查；默认不重复追加解析捕获。"""
        with self._lock:
            if rerun_rules:
                self.rule_results.clear()
                self.results_by_line.clear()
                self.results_by_rule.clear()
                for line in self.lines:
                    self._run_line(line)
                self._refresh_line_summaries()
            plans = self.evaluate(at_time=at_time)
            for plan in plans:
                self.commit_plan(plan)
            return {
                "batch_id": self.batch_id,
                "official_count": len(self.official_classifications),
                "disputed_count": len(self.disputes),
                "unmatched_count": len(self.unmatched_lines),
            }

    retry_classification = retry

    def rerun_dispute(self, dispute_or_key: Any) -> ClassificationDispute | None:
        if isinstance(dispute_or_key, ClassificationDispute):
            dispute = dispute_or_key
        else:
            key = self._resolve_line_key(dispute_or_key)
            dispute = self.disputes.get(key or "") if key else None
            if dispute is None and isinstance(dispute_or_key, str):
                dispute = next((item for item in self.disputes.values()
                                if item.dispute_id == dispute_or_key), None)
            if dispute is None:
                dispute = next((item for item in self.resolved_disputes.values()
                                if item.dispute_id == dispute_or_key), None)
            if dispute is None and isinstance(dispute_or_key, str):
                dispute = next((item for item in self.dispute_history
                                if item.dispute_id == dispute_or_key), None)
            if dispute is None:
                key = str(dispute_or_key)
                dispute = self.disputes.get(key) or self.resolved_disputes.get(key)
        if dispute is None:
            return None
        return dispute.replay()

    replay_dispute = rerun_dispute

    def review_dispute(self, dispute_or_key: Any) -> ClassificationDispute | None:
        return self.rerun_dispute(dispute_or_key)

    replay_conflict = review_dispute
    review_conflict = review_dispute

    def revise_rule(self, rule: Any = None, rule_id: str | None = None, *,
                    pattern: str | None = None, regex_pattern: str | None = None,
                    field_names: list[str] | str | None = None,
                    new_pattern: str | None = None, new_fields: list[str] | str | None = None,
                    state: str | None = "生效中", rerun: bool = True,
                    **changes: Any) -> dict[str, Any]:
        rid = rule_id or rule_id_of(rule)
        target = rule
        if target is None:
            target = next((item for item in self.rules if rule_id_of(item) == rid), None)
        if target is None:
            raise KeyError(f"批次中不存在规则：{rid}")
        self.register_rule(target)

        old_snapshot = {
            "rule_id": rid,
            "version": _attr(target, ("version", "revision"), 1),
            "regex_pattern": rule_pattern_of(target),
            "field_names": rule_field_names_of(target),
            "state": rule_state_of(target),
            "at": _now().isoformat(),
        }
        self.rule_revisions.setdefault(rid, []).append(old_snapshot)

        next_pattern = pattern if pattern is not None else regex_pattern
        next_pattern = next_pattern if next_pattern is not None else new_pattern
        next_fields = field_names if field_names is not None else new_fields
        if next_pattern is not None:
            self._set_rule_attr(target, ("regex_pattern", "pattern", "regex", "正则表达式"), next_pattern)
            compiled = getattr(target, "_compiled_re", None)
            if compiled is not None:
                try:
                    target._compiled_re = re.compile(next_pattern) if isinstance(next_pattern, str) else next_pattern
                except re.error:
                    target._compiled_re = None
        if next_fields is not None:
            fields = rule_field_names_of(type("R", (), {"fields": next_fields})()) if not isinstance(next_fields, list) else next_fields
            self._set_rule_attr(target, ("field_names", "fields", "字段定义"), fields)
        if state is not None:
            self._set_rule_attr(target, ("state", "status", "方案状态"), state)
        version = int(_attr(target, ("version", "revision", "规则版本"), 1) or 1) + 1
        self._set_rule_attr(target, ("version", "revision", "规则版本"), version)
        if hasattr(target, "revision"):
            try:
                target.revision = version
            except Exception:
                pass
        for key, value in changes.items():
            setattr(target, key, value)

        result = {"rule_id": rid, "version": version, "affected_line_keys": sorted(self.rule_line_hits.get(rid, set())),
                  "rerun_line_keys": [], "reclassified_line_keys": [], "unchanged_line_keys": []}
        if rerun:
            rerun_result = self.rerun_revised_rule(rule_id=rid)
            result.update(rerun_result)
            # 重跑结果用于补充键集合，不应覆盖本次修订的真实规则编号。
            result["rule_id"] = rid
        return result

    revise_and_rerun_rule = revise_rule

    @staticmethod
    def _set_rule_attr(rule: Any, names: tuple[str, ...], value: Any) -> None:
        if isinstance(rule, dict):
            for name in names:
                if name in rule:
                    rule[name] = value
                    return
            rule[names[0]] = value
            return
        for name in names:
            if hasattr(rule, name):
                try:
                    setattr(rule, name, value)
                    return
                except Exception:
                    pass
        try:
            setattr(rule, names[0], value)
        except Exception:
            pass

    def rerun_revised_rule(self, rule: Any = None, rule_id: str | None = None) -> dict[str, Any]:
        """只重跑曾经命中该规则的原行；其他行的正式记录和版本完全不触碰。"""
        rid = rule_id or rule_id_of(rule)
        affected = sorted(self.rule_line_hits.get(rid, set()))
        self.rule_rerun_keys[rid] = affected
        line_by_key = {line.line_key: line for line in self.lines}
        reclassified: list[str] = []
        changed: list[str] = []
        with self._lock:
            for key in affected:
                line = line_by_key.get(key)
                if line is None:
                    continue
                # 保留旧结果用于追溯；追加新版本结果，而不是删除被撤下规则的字段。
                old_for_rule = [r for r in self.results_by_line.get(key, []) if r.rule_id == rid]
                new_results = self._run_line(line, rule_ids=[rid])
                new_result = new_results[-1] if new_results else None
                self._refresh_line_summaries()
                plans = self.evaluate(selected_keys=[key])
                if plans:
                    before = self.official_classifications.get(key)
                    before_fp = before.fingerprint if before else None
                    official, did_change = self.commit_plan(plans[0])
                    if did_change or before_fp != official.fingerprint:
                        changed.append(key)
                    reclassified.append(key)
                else:
                    # 修订后可能不再形成无争议正式分类；evaluate 已更新 dispute/unmatched。
                    existing = self.official_classifications.pop(key, None)
                    if existing is not None:
                        # 不物理删除历史：标记为被争议/未匹配取代，保留 history。
                        existing.status = "superseded"
                        existing.state = "规则修订后待复核"
            untouched = [line.line_key for line in self.lines if line.line_key not in affected]
            return {
                "rule_id": rid,
                "rerun_line_keys": affected,
                "affected_line_keys": affected,
                "reclassified_line_keys": changed,
                "processed_line_keys": reclassified,
                "untouched_line_keys": untouched,
            }

    rerun_rule_impact = rerun_revised_rule
    rerun_affected_lines = rerun_revised_rule

    def _default_record_factory(self, plan: dict[str, Any]) -> EventRecord:
        key = plan["line_key"]
        fields = plan["fields"]
        host = fields.get("client_ip") or fields.get("hostname") or fields.get("host") or "unknown"
        return EventRecord(
            record_id=f"EVEN-DUAL-{_short_hash(key, 12)}",
            event_type=plan["event_type"],
            original_content=plan["raw_line"][:500],
            parsed_fields=dict(fields),
            masked_fields={},
            enriched_fields={},
            event_time=_now(),
            source_host=str(host),
            store_partition=f"{_now():%Y%m%d}",
            index_state="已写入",
        )


# 常见命名别名。
DualMatchVerificationBatch = DualMatchBatch
DualMatchCheckBatch = DualMatchBatch
DualMatchCheck = DualMatchBatch
DoubleMatchBatch = DualMatchBatch
DoubleMatchVerificationBatch = DualMatchBatch
DoubleMatchCheckBatch = DualMatchBatch
ParseMatchBatch = DualMatchBatch
ParseVerificationBatch = DualMatchBatch
ParseVerifyBatch = DualMatchBatch
FieldVerificationBatch = DualMatchBatch
FieldMatchBatch = DualMatchBatch
RuleMatchBatch = DualMatchBatch
RuleVerificationBatch = DualMatchBatch
DualRuleBatch = DualMatchBatch
DualRuleVerificationBatch = DualMatchBatch
CrossMatchBatch = DualMatchBatch
CrossRuleMatchBatch = DualMatchBatch
CrossRuleVerificationBatch = DualMatchBatch
PairedMatchBatch = DualMatchBatch
DualRuleConfirmationBatch = DualMatchBatch
ClassificationBatch = DualMatchBatch
LineMatchReport = ReportDict
DualMatchReport = ReportDict
ClassificationConflict = ClassificationDispute
ConflictRecord = ClassificationDispute
DisputedRecord = ClassificationDispute
FormalClassificationRecord = OfficialClassification
OfficialClassificationRecord = OfficialClassification
ConfirmedClassification = OfficialClassification


class DualMatchService(DualMatchBatch):
    """有多个批次时的登记/查询入口；本身也可直接作为一个批次使用。"""

    def __init__(self, entries: Any = None, rules: Iterable[Any] | None = None, **kwargs: Any) -> None:
        self.batches: list[DualMatchBatch] = []
        self.batches_by_id: dict[str, DualMatchBatch] = {}
        super().__init__(entries=entries, rules=rules, **kwargs)
        self.batches.append(self)
        self.batches_by_id[self.batch_id] = self

    def verify(self, entries: Any = None, rules: Iterable[Any] | None = None, **kwargs: Any) -> "DualMatchService":
        if entries is not None:
            self.set_entries(entries)
        if rules is not None:
            self.register_rules(rules)
        for key, value in kwargs.items():
            if key == "signoffs" and value is not None:
                for item in value:
                    self.sign_rule(**item) if isinstance(item, dict) else self.add_signoff(item)
            else:
                setattr(self, key, value)
        self.run()
        return self

    check = verify

    def create_batch(self, entries: Any = None, rules: Any = None, **kwargs: Any) -> DualMatchBatch:
        batch = DualMatchBatch(entries=entries, rules=rules, event_types=kwargs.pop("event_types", self.event_types),
                              record_factory=kwargs.pop("record_factory", self.record_factory), **kwargs)
        self.batches.append(batch)
        self.batches_by_id[batch.batch_id] = batch
        return batch

    def submit_logs(self, lines: Any, rules: Any = None, signoffs: Any = None, **kwargs: Any) -> dict[str, Any]:
        batch = self.create_batch(entries=lines, rules=rules, signoffs=signoffs, auto_run=True, **kwargs)
        return batch.submit()

    def get_batch(self, batch_id: str) -> DualMatchBatch | None:
        return self.batches_by_id.get(batch_id)


DualMatchVerifier = DualMatchService
DualRuleVerificationService = DualMatchService
ClassificationCoordinator = DualMatchService
OfficialClassificationRegistry = DualMatchService


def create_dual_match_batch(entries: Any = None, rules: Any = None, **kwargs: Any) -> DualMatchBatch:
    return DualMatchBatch(entries=entries, rules=rules, auto_run=kwargs.pop("auto_run", False), **kwargs)


def verify_dual_matches(entries: Any, rules: Any, **kwargs: Any) -> DualMatchBatch:
    return DualMatchBatch(entries=entries, rules=rules, auto_run=True, **kwargs)


def run_dual_match(entries: Any, rules: Any, **kwargs: Any) -> DualMatchBatch:
    batch = DualMatchBatch(entries=entries, rules=rules, **kwargs)
    batch.run()
    return batch


run_dual_match_verification = verify_dual_matches
create_verification_batch = create_dual_match_batch


def dual_match_and_classify(entries: Any, rules: Any, **kwargs: Any) -> tuple[DualMatchBatch, list[EventRecord]]:
    batch = DualMatchBatch(entries=entries, rules=rules, **kwargs)
    batch.run()
    return batch, batch.classify_events()


def __getattr__(name: str) -> Any:
    """未知但语义明确的命名也返回兼容实现，降低不同命名入口的导入成本。"""
    if name.startswith("_"):
        raise AttributeError(name)
    lower = name.lower()
    if "confirmation" in lower and lower.endswith("record"):
        return ConfirmationRecord
    if name.endswith("Batch") or "batch" in lower:
        return DualMatchBatch
    if any(token in lower for token in ("signoff", "sign_off", "confirmation", "approval")):
        return RuleSignOff
    if any(token in lower for token in ("dispute", "conflict")):
        return ClassificationDispute
    if any(token in lower for token in ("official", "formal")):
        return OfficialClassification
    if any(token in lower for token in ("matchresult", "ruleresult", "parseresult")):
        return RuleMatchResult
    if any(token in lower for token in ("service", "verifier", "coordinator", "registry")):
        return DualMatchService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
