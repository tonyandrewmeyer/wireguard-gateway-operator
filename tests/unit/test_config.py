# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm configuration unit tests."""

import ipaddress

import pytest
from ops import testing

import charm


def run_config_changed(config: dict[str, str | int]) -> testing.State:
    ctx = testing.Context(charm.Charm)
    return ctx.run(ctx.on.config_changed(), testing.State(config=config))


@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param("192.0.2.0/24", "192.0.2.0/24", id="one"),
        pytest.param(
            " 192.0.2.0/24 ,  2001:db8::/32 ", "192.0.2.0/24, 2001:db8::/32", id="whitespace"
        ),
        pytest.param(
            "192.0.2.0/24,,2001:db8::/32", "192.0.2.0/24, 2001:db8::/32", id="empty item"
        ),
        pytest.param("192.0.2.0/24,", "192.0.2.0/24", id="trailing comma"),
        pytest.param("192.0.2.1/24", "192.0.2.0/24", id="host bits set"),
    ],
)
def test_valid_advertise_prefixes(value: str, expected: str):
    """
    arrange: advertise-prefixes in each shape the hand-written parser accepted.
    act: run config_changed.
    assert: the unit is active and advertises the parsed prefixes.
    """
    state_out = run_config_changed({"advertise-prefixes": value})
    assert state_out.unit_status == testing.ActiveStatus(f"advertising prefixes: {expected}")


@pytest.mark.parametrize(
    "value, expected",
    [
        pytest.param("", [], id="empty"),
        pytest.param(" 10.0.0.1/24 ", ["10.0.0.1/24"], id="whitespace"),
        pytest.param(
            "10.0.0.1/24,,2001:db8::1/64,", ["10.0.0.1/24", "2001:db8::1/64"], id="empty items"
        ),
    ],
)
def test_valid_vips(value: str, expected: list[str]):
    """
    arrange: vips in each shape the hand-written parser accepted.
    act: load the config.
    assert: the VIPs are parsed, and the unit is active.
    """
    config = charm.CharmConfig(advertise_prefixes="192.0.2.0/24", vips=value)  # type: ignore[arg-type]
    assert config.vips == [ipaddress.ip_interface(vip) for vip in expected]
    state_out = run_config_changed({"advertise-prefixes": "192.0.2.0/24", "vips": value})
    assert isinstance(state_out.unit_status, testing.ActiveStatus)


@pytest.mark.parametrize("tunnels", [2, 3, 16])
def test_valid_tunnels(tunnels: int):
    """
    arrange: a valid number of tunnels.
    act: run config_changed.
    assert: the unit is active.
    """
    state_out = run_config_changed({"advertise-prefixes": "192.0.2.0/24", "tunnels": tunnels})
    assert isinstance(state_out.unit_status, testing.ActiveStatus)


def test_unset_options_get_their_defaults():
    """
    arrange: only the option the charm can't work without.
    act: load the config.
    assert: vips is empty and tunnels is the charmcraft.yaml default.
    """
    config = charm.CharmConfig(advertise_prefixes="192.0.2.0/24")  # type: ignore[arg-type]
    assert config.vips == []
    assert config.tunnels == 2


@pytest.mark.parametrize(
    "config, message",
    [
        pytest.param({}, "no advertise-prefixes configured", id="advertise-prefixes unset"),
        pytest.param(
            {"advertise-prefixes": ""}, "no advertise-prefixes configured", id="empty prefixes"
        ),
        pytest.param(
            {"advertise-prefixes": " , ,"},
            "no advertise-prefixes configured",
            id="only separators",
        ),
        pytest.param(
            {"advertise-prefixes": "192.0.2.0/24, 10.0.0.0/33"},
            "invalid advertise-prefixes: '10.0.0.0/33' is not an IPv4 or IPv6 prefix",
            id="invalid prefix",
        ),
        pytest.param(
            {"advertise-prefixes": "192.0.2.0/24", "vips": "10.0.0.1/24, not-an-ip"},
            "invalid vip in vips config: not-an-ip",
            id="invalid vip",
        ),
        pytest.param(
            {"advertise-prefixes": "192.0.2.0/24", "tunnels": 1},
            "tunnels configuration must be greater than 1",
            id="one tunnel",
        ),
        pytest.param(
            {"advertise-prefixes": "", "tunnels": 0},
            "no advertise-prefixes configured",
            id="first error wins",
        ),
    ],
)
def test_invalid_config_blocks(config: dict[str, str | int], message: str):
    """
    arrange: an invalid config.
    act: run config_changed.
    assert: the unit is blocked with the same one-line message as before load_config.
    """
    state_out = run_config_changed(config)
    assert state_out.unit_status == testing.BlockedStatus(message)


def test_invalid_config_blocks_on_other_events():
    """
    arrange: an invalid config.
    act: run update_status.
    assert: the unit is blocked, as on config_changed.
    """
    ctx = testing.Context(charm.Charm)
    state_out = ctx.run(ctx.on.update_status(), testing.State(config={"tunnels": 1}))
    assert state_out.unit_status == testing.BlockedStatus("no advertise-prefixes configured")


@pytest.mark.parametrize(
    "config, message",
    [
        pytest.param(
            {"advertise-prefixes": "192.0.2.0/24"},
            "relation(s) contains invalid data",
            id="valid config",
        ),
        pytest.param(
            {"advertise-prefixes": "192.0.2.0/24", "tunnels": 1},
            "tunnels configuration must be greater than 1",
            id="invalid config",
        ),
    ],
)
def test_config_errors_win_over_relation_errors(config: dict[str, str | int], message: str):
    """
    arrange: a relation with invalid remote data, and a valid or invalid config.
    act: run config_changed.
    assert: a config error is reported in place of the relation error.
    """
    ctx = testing.Context(charm.Charm)
    relation = testing.Relation(
        endpoint=charm.WIREGUARD_ROUTER_PROVIDER_RELATION,
        remote_units_data={1: {"ingress-address": "not-an-ip"}},
    )
    state_in = testing.State(config=config, relations=[relation])
    state_out = ctx.run(ctx.on.config_changed(), state_in)
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert state_out.unit_status.message.startswith(message)
