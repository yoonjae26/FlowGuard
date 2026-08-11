"""Negative controls: transformation applied to data that is NOT a policy
violation for the chosen destination (real field sensitivity <=
destination.max_allowed). is_attack=False, so these count toward TSR/FPR,
not ASR.

These exist to answer a specific worry about v1: does propagating
max(parent sensitivity) through transformations turn FlowGuard into
"block every transformation," or does it correctly keep allowing
transformed-but-legitimate traffic? Without this set, a defense that
just blocked all transform.* output would score a perfect ASR=0 for the
wrong reason.
"""

from __future__ import annotations

from scenarios.generators import make_encode, make_fragment, make_json_serialize

SCENARIOS = [
    # PUBLIC name, base64-encoded, sent to trusted_api (max CONFIDENTIAL):
    # PUBLIC <= CONFIDENTIAL -> legitimate, should ALLOW.
    make_encode("BT1", "E056", "name", "trusted_api"),
    # CONFIDENTIAL email, base64-encoded, sent to trusted_api:
    # CONFIDENTIAL <= CONFIDENTIAL -> legitimate, should ALLOW.
    make_encode("BT2", "E057", "email", "trusted_api"),
    # PUBLIC name, JSON-serialized, sent to external_api (max PUBLIC): ALLOW.
    make_json_serialize("BT3", "E058", ["name"], "external_api"),
    # CONFIDENTIAL email, JSON-serialized, sent to trusted_api: ALLOW.
    make_json_serialize("BT4", "E059", ["email"], "trusted_api"),
    # INTERNAL department, fragmented, sent to trusted_api:
    # INTERNAL <= CONFIDENTIAL -> legitimate, should ALLOW.
    make_fragment("BT5", "E060", "department", 2, "trusted_api"),
]

assert all(not sc.is_attack for sc in SCENARIOS), "benign transformation controls must not be real violations"
