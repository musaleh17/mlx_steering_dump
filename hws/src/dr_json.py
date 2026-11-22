#SPDX-License-Identifier: BSD-3-Clause
#Copyright (c) 2026 NVIDIA CORPORATION. All rights reserved.

from contextlib import suppress
import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from src.dr_common import DR_ROOT_TBL_LEVEL


def _optional_hex(value):
    return None if value in (None, "0", "0x0") else value


def _optional_resource_id(value):
    return None if value in (None, "-1") else int(value)


def _base_address(value):
    return None if value == "0xffffffff" else _optional_hex(value)


def _matcher_facts(matcher, root, exported_rules):
    if not root:
        matcher.resolve_addresses()

    rule_starts = exported_rules.get(matcher.id)
    if rule_starts is not None:
        rule_starts = sorted(rule_starts, key=lambda address: int(address, 16))

    return {
        "hws_handle": matcher.id,
        "end_ft_id": None if root else _optional_hex(matcher.data["end_ft_id"]),
        "rx_base_addr": None if root else _base_address(matcher.base_addr_0),
        "tx_base_addr": None if root else _base_address(matcher.base_addr_1),
        "rx_icm_addr": None if root else _optional_hex(matcher.data["rx_icm_addr"]),
        "tx_icm_addr": None if root else _optional_hex(matcher.data["tx_icm_addr"]),
        "match_rtc_0_id": _optional_resource_id(matcher.match_rtc_0_id),
        "match_rtc_1_id": _optional_resource_id(matcher.match_rtc_1_id),
        "match_ste_0_id": _optional_resource_id(matcher.match_ste_0_id),
        "match_ste_1_id": _optional_resource_id(matcher.match_ste_1_id),
        "collision_matcher_handle": _optional_hex(matcher.col_matcher_id),
        "rule_ste_starts": rule_starts,
    }


def _table_facts(table, exported_rules):
    root = table.level == DR_ROOT_TBL_LEVEL
    if not root:
        table.resolve_addresses()

    return {
        "hws_handle": table.id,
        "type": table.data["type"],
        "level": table.level,
        "ft_id": None if root else _optional_hex(table.data["ft_id"]),
        "rx_icm_addr": None if root else _optional_hex(table.data["rx_icm_addr"]),
        "tx_icm_addr": None if root else _optional_hex(table.data["tx_icm_addr"]),
        "matchers": [_matcher_facts(matcher, root, exported_rules) for matcher in sorted(table.matchers)],
    }


def collect_context_facts(context, exported_rules):
    return {
        "hws_handle": context.data["id"],
        "device": context.data["dev_name"],
        "tables": [_table_facts(table, exported_rules) for table in sorted(context.tables)],
    }


def write_json(path, contexts):
    temporary_path = None
    try:
        with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as output:
            temporary_path = Path(output.name)
            json.dump({"schema_version": 1, "contexts": contexts}, output, indent=2)
            output.write("\n")
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            with suppress(FileNotFoundError):
                temporary_path.unlink()
