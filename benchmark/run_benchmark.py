#!/usr/bin/env python3
"""
AXIOM RED — Benchmark Harness
Runs the agent against sandbox targets, maps findings to ground-truth OWASP classes,
and reports coverage + precision + wall-clock time. Writes benchmark/results.json.
"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.core.react_agent import run_agent

# Ground truth: OWASP categories each target is KNOWN to contain (extend as you validate).
GROUND_TRUTH = {
    "http://localhost:5000": {"A01", "A02", "A03", "A05"},   # custom API: IDOR, JWT, SQLi/CMDi/XSS, config/redis
    "http://localhost:3000": {"A01", "A03", "A07"},           # OWASP Juice Shop (adjust after a validation run)
    "http://localhost:8080": {"A01", "A03", "A05"},           # DVWA
}

def benchmark_target(target: str) -> dict:
    t0 = time.time()
    state = run_agent(target)
    elapsed = round(time.time() - t0, 1)
    found_ids = {f.owasp_id for f in state.findings if f.owasp_id}
    expected = GROUND_TRUTH.get(target, set())
    covered = found_ids & expected
    extra = found_ids - expected          # categories found beyond ground truth (inspect for FPs)
    coverage = round(len(covered) / len(expected) * 100, 1) if expected else 0.0
    return {
        "target": target,
        "findings": len(state.findings),
        "owasp_found": sorted(found_ids),
        "owasp_expected": sorted(expected),
        "covered": sorted(covered),
        "beyond_ground_truth": sorted(extra),
        "coverage_pct": coverage,
        "replans": state.replan_count,
        "seconds": elapsed,
        "evidence_root": getattr(state, "evidence_root_hash", ""),
    }

def main():
    targets = sys.argv[1:] or list(GROUND_TRUTH.keys())
    results = []
    for t in targets:
        try:
            results.append(benchmark_target(t))
        except Exception as e:
            results.append({"target": t, "error": str(e)})
    out_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    # console summary
    print("\n" + "=" * 68)
    print("  AXIOM RED — Benchmark Results")
    print("=" * 68)
    for r in results:
        if "error" in r:
            print(f"  {r['target']:32} ERROR: {r['error']}")
        else:
            print(f"  {r['target']:32} {r['coverage_pct']:5}%  "
                  f"{len(r['covered'])}/{len(r['owasp_expected'])} classes  "
                  f"{r['findings']} findings  {r['seconds']}s  replans={r['replans']}")
    print("=" * 68)

if __name__ == "__main__":
    main()
