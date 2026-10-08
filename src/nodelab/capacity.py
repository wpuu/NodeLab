"""Bounded, synthetic-only offline capacity arithmetic; no provisioning or IO in simulate."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import json
import os
import stat
from pathlib import Path
import re
import sys

MAX_INPUT_BYTES = 512 * 1024
MAX_ROWS = 1000
UNITS = {"GB": Decimal(10**9), "GiB": Decimal(2**30)}


class CapacityInputError(ValueError):
    """Never echo input values or filesystem paths in errors."""


def require(condition, code="INVALID_INPUT"):
    if not condition:
        raise CapacityInputError(code)


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def number(value):
    require(type(value) in (int, float, str))
    if type(value) is int:
        require(0 <= value <= 10**18, "INVALID_NUMBER")
    require(len(str(value)) <= 40)
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise CapacityInputError("INVALID_NUMBER") from None
    require(result.is_finite() and 0 <= result <= Decimal("1e18"), "INVALID_NUMBER")
    # Bound precision/exponents to keep arithmetic and serialized output bounded.
    require(result.as_tuple().exponent >= -9, "INVALID_NUMBER")
    return result


def quantity(value):
    fields(value, "amount unit")
    require(type(value["unit"]) is str and value["unit"] in UNITS, "INVALID_UNIT")
    result = number(value["amount"]) * UNITS[value["unit"]]
    require(result == result.to_integral_value(), "FRACTIONAL_BYTE")
    return int(result)


def instant(value):
    require(type(value) is str and len(value) <= 40, "INVALID_TIME")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CapacityInputError("INVALID_TIME") from None
    require(result.tzinfo is not None, "INVALID_TIME")
    return result.astimezone(timezone.utc)


def token(value, prefix):
    require(type(value) is str and re.fullmatch(prefix + r"[0-9]{4}", value) is not None)
    return value


def evidence(value):
    if value is not None:
        token(value, "E")
    return value is not None


def status(value, allowed):
    require(type(value) is str and value in allowed)
    return value


def simulate(document, *, now):
    with localcontext() as context:
        context.prec = 64
        return _simulate(document, now=now)


def _simulate(document, *, now):
    """Evaluate one explicit quota window. Evidence IDs are assertions, not verification.

    Only synthetic IDs/enum fields accepted. Unknowns exclude capacity, never imply zero cost.
    The caller supplies an aware clock to make testing and past scenario replay deterministic.
    """
    require(isinstance(now, datetime) and now.tzinfo is not None, "INVALID_TIME")
    fields(document, "schema_version synthetic_only window_start window_end reserve_ratio free advanced groups resources")
    require(type(document["schema_version"]) is int and document["schema_version"] == 1)
    require(document["synthetic_only"] is True, "SYNTHETIC_ONLY_REQUIRED")
    start, end = instant(document["window_start"]), instant(document["window_end"])
    require(now <= start < end, "INVALID_WINDOW")
    reserve = number(document["reserve_ratio"])
    require(reserve <= 1, "INVALID_RESERVE")
    demand = 0
    for tier in ("free", "advanced"):
        row = document[tier]
        fields(row, "people per_person")
        require(type(row["people"]) is int and 0 <= row["people"] <= 10**9)
        demand += row["people"] * quantity(row["per_person"])
    groups, resources = document["groups"], document["resources"]
    require(type(groups) is list and type(resources) is list)
    require(len(groups) <= MAX_ROWS and len(resources) <= MAX_ROWS, "TOO_MANY_ROWS")
    group_map, remaining, eligible, blocked = {}, {}, {}, {}
    for g in groups:
        fields(g, "id quota used quota_evidence verified window_start window_end cost currency cost_complete service_hours")
        gid = token(g["id"], "G")
        require(gid not in group_map, "DUPLICATE_GROUP")
        quota = None if g["quota"] is None else quantity(g["quota"])
        used = None if g["used"] is None else quantity(g["used"])
        require(quota is None or used is None or used <= quota, "OVER_QUOTA")
        proof = evidence(g["quota_evidence"])
        checked = status(g["verified"], {"verified", "unknown"})
        gs, ge = instant(g["window_start"]), instant(g["window_end"])
        require(gs < ge, "INVALID_WINDOW")
        require(type(g["cost_complete"]) is bool)
        require(type(g["currency"]) is str and g["currency"] in {"CNY", "USD", "EUR"})
        if g["cost"] is not None:
            number(g["cost"])
        if g["service_hours"] is not None:
            number(g["service_hours"])
        require(not g["cost_complete"] or g["cost"] is not None, "INCOMPLETE_COST")
        group_map[gid] = g
        reasons = []
        if quota is None or used is None or not proof or checked != "verified":
            reasons.append("QUOTA_UNVERIFIED")
        # No prorating or cross-period addition: inputs describe this exact planning window.
        if (gs, ge) != (start, end):
            reasons.append("QUOTA_WINDOW_MISMATCH")
        blocked[gid] = reasons
        remaining[gid] = quota - used if quota is not None and used is not None else 0
        eligible[gid] = []
    seen, rejected, ungrouped = set(), [], []
    for r in resources:
        fields(r, "id group source source_evidence use_authorization supply_authorization authorization_evidence expires_at verified")
        rid = token(r["id"], "R")
        gid = None if r["group"] is None else token(r["group"], "G")
        require(rid not in seen, "DUPLICATE_RESOURCE")
        require(gid is None or gid in group_map, "UNKNOWN_GROUP")
        seen.add(rid)
        source = status(r["source"], {"owned", "licensed", "third_party_shared", "unknown"})
        source_proof = evidence(r["source_evidence"])
        auth_proof = evidence(r["authorization_evidence"])
        use = status(r["use_authorization"], {"allowed", "denied", "unknown"})
        supply = status(r["supply_authorization"], {"allowed", "denied", "unknown"})
        checked = status(r["verified"], {"verified", "unknown"})
        expiry = None if r["expires_at"] is None else instant(r["expires_at"])
        reasons = []
        if gid is None:
            ungrouped.append(rid)
            reasons.append("SHARED_GROUP_UNKNOWN")
        if source == "unknown" or not source_proof:
            reasons.append("SOURCE_UNVERIFIED")
        if use != "allowed" or supply != "allowed" or not auth_proof:
            reasons.append("AUTHORIZATION_UNVERIFIED")
        if checked != "verified":
            reasons.append("RESOURCE_UNVERIFIED")
        if expiry is None or expiry < end:
            reasons.append("EXPIRY_NOT_COVERING_WINDOW")
        if reasons:
            rejected.append({"resource": rid, "reasons": reasons})
        else:
            eligible[gid].append(rid)
    available = 0
    costs, missing_costs, hours, missing_hours, counted, excluded = {}, [], Decimal(0), [], [], []
    # Costs cover the whole listed ledger, including resources excluded from allocation.
    # This avoids hiding sunk/ongoing costs of unusable resources.
    for gid, g in group_map.items():
        if g["cost"] is not None:
            currency = g["currency"]
            costs[currency] = costs.get(currency, Decimal(0)) + number(g["cost"])
        if not g["cost_complete"] or g["cost"] is None:
            missing_costs.append(gid)
        if g["service_hours"] is None:
            missing_hours.append(gid)
        else:
            hours += number(g["service_hours"])
        reasons = blocked[gid] + ([] if eligible[gid] else ["NO_ELIGIBLE_RESOURCE"])
        if reasons:
            excluded.append({"group": gid, "reasons": reasons})
        else:
            available += remaining[gid]
            counted.append(gid)
    allocatable = int(Decimal(available) * (1 - reserve))
    return {
        "schema_version": 1, "mode": "synthetic_offline_capacity", "network_used": False,
        "assumptions_only": True, "allocation_performed": False,
        "service_ready": False, "reliability_assessed": False, "committable_capacity_bytes": 0,
        "available_bytes": available, "allocatable_bytes": allocatable,
        "demand_bytes": demand, "shortfall_bytes": max(0, demand - allocatable),
        "capacity_sufficient": demand <= allocatable,
        "counted_groups": counted, "excluded_groups": excluded, "excluded_resources": rejected,
        "known_cost_subtotals": {k: str(v) for k, v in sorted(costs.items())},
        "missing_cost_groups": missing_costs, "cost_scope": "all_listed_groups_for_window",
        "ungrouped_resources_cost_and_hours_unknown": ungrouped,
        "known_service_hours": str(hours), "missing_service_hours_groups": missing_hours,
        "profitability_assessed": False,
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise CapacityInputError("INVALID_ARGUMENTS")


def main(argv=None):
    parser = _SafeArgumentParser(description="离线合成容量测算：假设数据，不分配资源、不联网、不预测盈利")
    parser.add_argument("scenario", help="仅匿名合成 JSON；不要输入实际账号、账单或节点")
    parser.add_argument("--now", help="显式 ISO 8601 时钟，用于可复现的假设场景")
    try:
        args = parser.parse_args(argv)
        # Only an ordinary local file; never URLs, pipes, devices, symlinks or Windows shares.
        path = Path(os.path.abspath(args.scenario))
        if os.name == "nt":
            import ctypes
            require(len(path.drive) == 2 and path.drive[1] == ":" and not path.is_reserved())
            require(not any(":" in part for part in path.parts[1:]))
            require(ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) in {2, 3})
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            info = current.lstat()
            require(not stat.S_ISLNK(info.st_mode))
            require(not getattr(info, "st_file_attributes", 0) & (0x400 | 0x1000 | 0x40000 | 0x400000))
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_INPUT_BYTES)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(stat.S_ISREG(opened.st_mode) and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
            raw = stream.read(MAX_INPUT_BYTES + 1)
        require(len(raw) <= MAX_INPUT_BYTES, "INPUT_TOO_LARGE")
        document = json.loads(raw, object_pairs_hook=_unique_object)
        report = simulate(document, now=instant(args.now) if args.now else datetime.now(timezone.utc))
    except (CapacityInputError, ValueError, OSError, RecursionError, OverflowError):
        print(json.dumps({"error": "CAPACITY_INPUT_REJECTED", "network_used": False}), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
