# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Strict JSON parsing for request bodies.

Parser differentials are a classic bypass: {"role":"admin","role":"viewer"} is "viewer" to a last-wins
parser and "admin" to a first-wins one. We refuse duplicate keys and non-standard constants outright, so
the gateway and the upstream server can never disagree about what a request says.
"""
import json


class UnsafeJSON(ValueError):
    pass


def _pairs(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise UnsafeJSON("duplicate keys are not allowed")
        seen.add(key)
    return dict(pairs)


def _constant(_name):
    raise UnsafeJSON("non-standard JSON constant")


def strict_loads(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except RecursionError:
        raise UnsafeJSON("nesting too deep")
