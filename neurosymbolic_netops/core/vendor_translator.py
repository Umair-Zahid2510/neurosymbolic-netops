"""Multi-vendor configuration translation via the IR, with behavioural validation in Batfish.

translate(ios_text, target) : parse IOS -> IR -> render target dialect (cisco_ios | juniper_junos | arista_eos)
validate_behaviour(...)     : render a whole network in a target dialect, load it into Batfish,
                              evaluate the same intents and BGP session table, and compare with the
                              IOS rendering of the same IR. Equivalence is claimed ONLY for networks
                              where this comparison passes (no SMT proof; see LIMITATIONS.md).

Replaces the pre-audit regex translator, whose token-overlap "equivalence check" accepted a
wrong MTU and rejected its own output (IMPLEMENTATION_AUDIT.md section 3.8).
"""

from __future__ import annotations

from typing import Dict, Literal

from core.config_ir import Network
from core.parsers.ios import parse_ios
from core.renderers.ios import render_ios
from core.renderers.ios import ios_interface_name
from core.renderers.vendors import eos_ifname, junos_ifname, render_eos, render_junos

Dialect = Literal["cisco_ios", "juniper_junos", "arista_eos"]
RENDER = {"cisco_ios": render_ios, "juniper_junos": render_junos, "arista_eos": render_eos}
UNSUPPORTED = {
    "juniper_junos": ["IOS 'log' keyword on ACL entries is not translated (Junos uses 'then syslog')",
                      "speed/duplex statements are platform dependent",
                      "IOS implicit BGP re-advertisement is modelled with an explicit export policy"],
    "arista_eos": ["ACL 'log' keyword not translated", "duplex is folded into 'speed forced'"],
}


class TranslationError(ValueError):
    pass


def translate(ios_text: str, target: Dialect, hostname_hint: str = None) -> str:
    dev = parse_ios(ios_text, hostname_hint)
    if dev.unsupported_lines:
        raise TranslationError(f"source has lines outside the IR, refusing to translate: {dev.unsupported_lines[:5]}")
    return RENDER[target](dev)


def validate_behaviour(network: Network, target: Dialect, topology, intents, host: str = "localhost") -> Dict:
    """Compare Batfish's view of the IOS rendering with its view of the ``target`` rendering."""
    from core.verification.batfish_backend import BatfishBackend

    class _Rendered(BatfishBackend):
        def __init__(self, render, tag, ifname):
            super().__init__(topology, host=host, network_name=f"netops-xlate-{tag}")
            self._render, self._tag, self.ifname = render, tag, ifname

        def load_snapshot(self, net):
            import tempfile
            from pathlib import Path
            import hashlib
            bf = self._session()
            texts = {dev: self._render(cfg) for dev, cfg in sorted(net.items())}
            name = f"{self._tag}_" + hashlib.sha256(repr(sorted(texts.items())).encode()).hexdigest()[:12]
            if name not in bf.list_snapshots():
                d = Path(tempfile.gettempdir()) / "netops_xlate" / name / "configs"
                d.mkdir(parents=True, exist_ok=True)
                for dev, text in texts.items():
                    (d / f"{dev}.cfg").write_text(text, encoding="utf-8")
                bf.init_snapshot(str(d.parent), name=name, overwrite=True)
            else:
                bf.set_snapshot(name)
            return name

    ifnames = {"cisco_ios": ios_interface_name, "arista_eos": eos_ifname,
               "juniper_junos": lambda n: junos_ifname(n) + ".0"}
    ref = _Rendered(render_ios, "ios", ios_interface_name).verify(network, intents)
    tgt_backend = _Rendered(RENDER[target], target.split("_")[-1], ifnames[target])
    tgt = tgt_backend.verify(network, intents)
    warnings = tgt_backend.parse_warnings() if not tgt.parse_issues else []
    per_intent = {c.intent_id: c.passed for c in ref.checks}
    diff = {c.intent_id: (per_intent.get(c.intent_id), c.passed) for c in tgt.checks if per_intent.get(c.intent_id) != c.passed}
    return {"target": target, "equivalent_on_intents": not diff and not tgt.parse_issues,
            "ios_violated": ref.violated(), "target_violated": tgt.violated(), "differences": diff,
            "target_parse_issues": tgt.parse_issues, "target_parse_warnings": warnings[:20],
            "unsupported_notes": UNSUPPORTED.get(target, [])}
