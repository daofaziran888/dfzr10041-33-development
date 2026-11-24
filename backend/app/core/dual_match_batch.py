"""兼容不同命名入口：双匹配核验批次。"""
from app.core.dual_match import *  # noqa: F401,F403
from app.core.dual_match import (  # noqa: F401
    ClassificationDispute,
    DualMatchBatch,
    DualMatchVerificationBatch,
    OfficialClassification,
    RuleMatchResult,
    RuleSignOff,
    create_dual_match_batch,
    verify_dual_matches,
)
