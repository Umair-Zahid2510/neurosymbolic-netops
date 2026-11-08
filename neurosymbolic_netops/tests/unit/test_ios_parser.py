import json

import pytest

from core.config_ir import AclRule
from core.parsers.ios import ParseError, canonical_interface_name, parse_acl_rule, parse_ios
from core.renderers.ios import render_ios
from tests.conftest import ROOT


def test_base_configs_parse_without_unsupported_lines(testbed):
    for dev, cfg in testbed.network.items():
        assert cfg.unsupported_lines == [], dev
        assert cfg.bgp is not None


@pytest.mark.parametrize("dev", ["Leaf-1", "Leaf-2", "Spine-1", "Spine-2"])
def test_render_parse_round_trip(testbed, dev):
    cfg = testbed.network[dev]
    assert parse_ios(render_ios(cfg), dev) == cfg


def test_legacy_dataset_configs_parse_and_round_trip():
    scen = json.loads((ROOT / "dataset" / "ground_truth_faults.json").read_text())
    scen += json.loads((ROOT / "dataset" / "advanced_stress_faults.json").read_text())
    for s in scen:
        for dev, text in s["corrupted_configs"].items():
            cfg = parse_ios(text, dev)
            assert cfg.unsupported_lines == [], (s["incident_id"], dev)
            assert parse_ios(render_ios(cfg), dev) == cfg


def test_unknown_lines_are_reported_not_dropped():
    cfg = parse_ios("hostname X\ninterface eth1\n ip ospf cost 10\nsnmp-server community foo RO\n")
    assert any("ip ospf cost" in line for line in cfg.unsupported_lines)
    assert any("snmp-server" in line for line in cfg.unsupported_lines)


def test_acl_rule_parsing_wildcards_hosts_ports():
    r = parse_acl_rule("deny tcp 10.1.0.0 0.0.255.255 host 10.1.20.10 eq 443 log")
    assert (r.src, r.dst, r.dst_port, r.log) == ("10.1.0.0/16", "10.1.20.10/32", 443, True)
    assert parse_acl_rule("permit ip any any") == AclRule(action="permit")
    with pytest.raises(ParseError):
        parse_acl_rule("deny ip 10.0.0.0 0.255.0.255 any")  # non-contiguous wildcard


def test_interface_name_canonicalisation():
    assert canonical_interface_name("GigabitEthernet0/2") == "eth2"
    assert canonical_interface_name("Ethernet10") == "eth10"
    assert canonical_interface_name("Vlan20") == "vlan20"


def test_bgp_activation_semantics():
    text = ("router bgp 1\n no bgp default ipv4-unicast\n neighbor 1.1.1.1 remote-as 2\n"
            " neighbor 2.2.2.2 remote-as 3\n address-family ipv4\n  neighbor 1.1.1.1 activate\n exit-address-family\n")
    cfg = parse_ios(text)
    assert cfg.bgp.neighbors["1.1.1.1"].activated and not cfg.bgp.neighbors["2.2.2.2"].activated
    legacy = parse_ios("router bgp 1\n neighbor 1.1.1.1 remote-as 2\n no neighbor 1.1.1.1 activate\n")
    assert legacy.bgp.neighbors["1.1.1.1"].activated is False
