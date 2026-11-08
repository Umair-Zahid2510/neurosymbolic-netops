"""Compatibility facade (pre-audit module name).

The pre-audit file contained no LLM call at all (a rule cascade with incident-ID branches). Real
providers are in ``agent/llm`` (Gemini, OpenAI, replay); LLM agents in ``agent/llm_agents.py``;
the deterministic baseline in ``agent/rule_based_diagnoser.py``.
"""
from agent.llm.base import LLMError, LLMProvider, provider_from_env, run_structured  # noqa: F401
from agent.llm_agents import LLMDiagnoser, LLMPlanner  # noqa: F401
