import pytest

from core.config_ir import AclRule
from core.patch_ops import (BindAcl, CreateAcl, PatchError, PatchPlan, RemoveAclRule, SetBgpNetwork,
                            SetInterfaceEnabled, SetInterfaceMtu, apply_plan, render_diff)


def plan(*ops):
    return PatchPlan(ops=list(ops))


def test_apply_is_pure(net):
    before = net["Leaf-1"].model_copy(deep=True)
    apply_plan(net, plan(SetInterfaceEnabled(device="Leaf-1", interface="eth1", enabled=False)))
    assert net["Leaf-1"] == before


def test_interface_scoped_changes_regression_audit_p3(net):
    # Legacy regex actuator produced "no no shutdown", changed MTU device-wide and removed every
    # ACL binding. Typed ops are interface-scoped.
    shut = apply_plan(net, plan(SetInterfaceEnabled(device="Leaf-2", interface="eth2", enabled=False)))
    fixed = apply_plan(shut, plan(SetInterfaceEnabled(device="Leaf-2", interface="eth2", enabled=True)))
    assert fixed == net
    m = apply_plan(net, plan(SetInterfaceMtu(device="Leaf-2", interface="eth1", mtu=1400)))
    assert m["Leaf-2"].interfaces["eth1"].mtu == 1400 and m["Leaf-2"].interfaces["eth2"].mtu == 1500
    u = apply_plan(net, plan(BindAcl(device="Leaf-1", interface="eth1", direction="in", acl=None)))
    assert u["Leaf-1"].interfaces["eth1"].acl_in is None
    assert u["Leaf-1"].interfaces["eth2"].acl_in == "PERIMETER_SECURITY_POLICY"
    assert "no no shutdown" not in render_diff(shut, fixed)


@pytest.mark.parametrize("op", [
    SetInterfaceEnabled(device="Nope", interface="eth1", enabled=True),
    SetInterfaceEnabled(device="Leaf-1", interface="eth9", enabled=True),
    RemoveAclRule(device="Leaf-1", acl="PERIMETER_SECURITY_POLICY", rule=AclRule(action="deny", src="10.9.0.0/16")),
    BindAcl(device="Leaf-1", interface="eth1", direction="in", acl="MISSING"),
    SetBgpNetwork(device="Leaf-1", prefix="10.1.10.0/24", present=True),
    CreateAcl(device="Leaf-1", acl="PERIMETER_SECURITY_POLICY", rules=[AclRule(action="permit")]),
    CreateAcl(device="Leaf-1", acl="PERIMETER_SECURITY_POLICY", delete=True),  # still bound
])
def test_invalid_ops_raise(net, op):
    with pytest.raises(PatchError):
        apply_plan(net, plan(op))


def test_plan_hash_is_stable_and_content_sensitive():
    a = plan(SetInterfaceMtu(device="Leaf-1", interface="eth1", mtu=1500))
    b = plan(SetInterfaceMtu(device="Leaf-1", interface="eth1", mtu=1500))
    c = plan(SetInterfaceMtu(device="Leaf-1", interface="eth1", mtu=1400))
    assert a.plan_hash() == b.plan_hash() != c.plan_hash()


def test_plan_json_round_trip():
    p = plan(RemoveAclRule(device="Leaf-1", acl="X", rule=AclRule(action="deny", src="10.1.20.0/24")),
             SetBgpNetwork(device="Leaf-1", prefix="10.1.10.0/24", present=False))
    assert PatchPlan.model_validate_json(p.model_dump_json()) == p
