#!/usr/bin/env python3
"""
AXIOM RED — Evidence Bundle Verifier
Usage:  python verify.py reports/evidence_<session>.json
Exit code 0 = intact, 1 = tampered/invalid. Re-walks the SHA-256 chain independently.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent.core.evidence import verify_bundle


def main():
    if len(sys.argv) != 2:
        print("Usage: python verify.py <evidence_bundle.json>")
        sys.exit(2)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        sys.exit(2)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    res = verify_bundle(path)
    print("=" * 60)
    print("  AXIOM RED -- Evidence Integrity Verification")
    print("=" * 60)
    print(f"  Bundle        : {path}")
    print(f"  Records       : {res['record_count']}")
    print(f"  Stored root   : {res['stored_root'][:32]}...")
    print(f"  Recomputed    : {res['recomputed_root'][:32]}...")
    print("-" * 60)
    if res["ok"]:
        print("  RESULT: [OK] INTACT -- chain verified, no tampering detected.")
        sys.exit(0)
    else:
        print(f"  RESULT: [TAMPERED] -- first broken record at seq {res['first_bad_seq']}.")
        print("  The exported evidence has been altered since sealing.")
        sys.exit(1)


if __name__ == "__main__":
    main()
