"""
AXIOM RED — Forensic Evidence Chain
Tamper-evident, hash-chained sealing of the engagement record (activity log + findings).
Each record is linked by SHA-256 to its predecessor; any post-hoc edit breaks the chain.
"""

import hashlib
import json
import os
from datetime import datetime

GENESIS = "0" * 64


def canonical(obj) -> str:
    """Deterministic JSON serialization (stable key order, no incidental whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(prev_hash: str, core: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(core)).encode("utf-8")).hexdigest()


def build_chain(records: list) -> tuple:
    """Seal an ordered list of record dicts into a hash chain. Returns (chain, root_hash)."""
    chain, prev = [], GENESIS
    for i, rec in enumerate(records):
        core = {"seq": i, "data": rec}
        h = _entry_hash(prev, core)
        chain.append({"seq": i, "prev_hash": prev, "entry_hash": h, "data": rec})
        prev = h
    return chain, prev


def seal_state(state) -> tuple:
    """Build the ordered evidence record list from an AgentState and seal it."""
    records = []
    for l in state.activity_log:
        d = l.model_dump() if hasattr(l, "model_dump") else dict(l)
        records.append({"kind": "log", **d})
    for f in state.findings:
        d = f.model_dump() if hasattr(f, "model_dump") else dict(f)
        records.append({"kind": "finding", **d})
    return build_chain(records)


def export_bundle(state, out_dir: str) -> tuple:
    """Write a sealed evidence bundle to disk. Returns (path, root_hash)."""
    os.makedirs(out_dir, exist_ok=True)
    chain, root = seal_state(state)
    bundle = {
        "tool": "AXIOM RED",
        "session_id": getattr(state, "session_id", ""),
        "target": getattr(state, "target", ""),
        "generated_at": datetime.now().isoformat(),
        "algorithm": "sha256-chain",
        "genesis": GENESIS,
        "root_hash": root,
        "record_count": len(chain),
        "chain": chain,
    }
    path = os.path.join(out_dir, f"evidence_{getattr(state,'session_id','session')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return path, root


def verify_bundle(path: str) -> dict:
    """Recompute the chain from data and compare to the sealed hashes/root.
    Returns {ok, first_bad_seq, recomputed_root, stored_root, record_count}."""
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    chain = bundle.get("chain", [])
    stored_root = bundle.get("root_hash", "")
    prev = bundle.get("genesis", GENESIS)
    first_bad = None
    for node in chain:
        core = {"seq": node["seq"], "data": node["data"]}
        recomputed = _entry_hash(prev, core)
        if recomputed != node.get("entry_hash") or node.get("prev_hash") != prev:
            if first_bad is None:
                first_bad = node["seq"]
        prev = recomputed  # walk on recomputed value so a single edit cascades
    ok = (prev == stored_root) and (first_bad is None)
    return {
        "ok": ok,
        "first_bad_seq": first_bad,
        "recomputed_root": prev,
        "stored_root": stored_root,
        "record_count": len(chain),
    }
