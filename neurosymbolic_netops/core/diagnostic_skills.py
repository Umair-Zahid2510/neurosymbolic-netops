"""Compatibility facade (pre-audit module name). Typed read-only skills now live in ``core/skills``."""
from core.skills.base import Skill, SkillCall, SkillContext, SkillRegistry  # noqa: F401
from core.skills.library import build_registry  # noqa: F401
