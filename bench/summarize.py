# SPDX-License-Identifier: Apache-2.0
"""Turn one run directory (results/<id>/) into summary.json and summary.md.

Standard library only; run.sh runs it in a python container.
"""
import json
import sys
from pathlib import Path

SCENARIOS = ["clean-get", "clean-post", "attack"]
TARGET_ORDER = ["direct", "lightwaf", "lightwaf-strict", "modsec-pl1", "modsec-pl2", "modsec-strict"]
LABELS = {
    "direct": "No WAF (backend direct)",
    "lightwaf": "Light WAF (PL2, threshold 5)",
    "lightwaf-strict": "Light WAF strict (PL4, threshold 3)",
    "modsec-pl1": "ModSecurity + CRS (PL1, threshold 5)",
    "modsec-pl2": "ModSecurity + CRS (PL2, threshold 5)",
    "modsec-strict": "ModSecurity + CRS strict (PL4, threshold 3)",
}


def load_perf(perf_dir: Path) -> dict:
    perf = {}
    for f in sorted(perf_dir.glob("*.json")):
        target, scenario, mode = f.stem.split(".")
        data = json.loads(f.read_text())
        s, p = data["summary"], data["latencyPercentiles"]
        codes = {str(k): v for k, v in (data.get("statusCodeDistribution") or {}).items()}
        perf.setdefault(target, {}).setdefault(scenario, {})[mode] = {
            "rps": s["requestsPerSec"],
            "success_rate": s["successRate"],
            "p50_ms": p["p50"] * 1000,
            "p90_ms": p["p90"] * 1000,
            "p99_ms": p["p99"] * 1000,
            "p999_ms": p["p99.9"] * 1000,
            "status_codes": codes,
            "errors": data.get("errorDistribution") or {},
        }
    for f in perf_dir.glob("*.memory.txt"):
        perf.setdefault(f.name.split(".")[0], {})["memory"] = f.read_text().strip()
    return perf


def load_gotestwaf(gtw_dir: Path) -> dict:
    """The gotestwaf 0.5 JSON report: `summary.true_positive_tests` / `summary.true_negative_tests`."""
    out = {}
    for f in sorted(gtw_dir.glob("*.json")):
        data = json.loads(f.read_text())
        tp = data["summary"]["true_positive_tests"]
        tn = data["summary"]["true_negative_tests"]
        cases = {}
        for test_set, by_case in (tp.get("test_sets") or {}).items():
            for case, r in by_case.items():
                if r["sent"]:
                    cases[f"{test_set}/{case}"] = {"blocked": r["blocked"], "sent": r["sent"]}
        out[f.stem] = {
            "score": data["score"],
            "tp_score": tp["score"],
            "tp_blocked": tp["summary"]["blocked_tests"],
            "tp_sent": tp["summary"]["total_sent"],
            "tp_unresolved": tp["summary"]["unresolved_tests"],
            "tn_score": tn["score"],
            "tn_passed": tn["summary"]["bypassed_tests"],
            "tn_sent": tn["summary"]["total_sent"],
            "cases": cases,
        }
    return out


def ordered(keys):
    return [t for t in TARGET_ORDER if t in keys] + sorted(k for k in keys if k not in TARGET_ORDER)


def fmt(v, digits=2):
    return "–" if v is None else f"{v:.{digits}f}"


def parse_env(text: str) -> dict:
    """env.txt: one key=value per line."""
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def render(env: str, perf: dict, gtw: dict) -> str:
    rate = int(parse_env(env).get("rate", 0)) or None
    lines = ["# Benchmark results", "", "```", env.strip(), "```", ""]
    base = perf.get("direct", {})
    for scenario in SCENARIOS:
        lines += [f"## {scenario}", "",
                  "| Target | p50 ms | p99 ms | p99.9 ms | added p99 ms | max req/s | max vs direct | status codes |",
                  "|---|---:|---:|---:|---:|---:|---:|---|"]
        for t in ordered(perf):
            fixed = perf[t].get(scenario, {}).get("fixed")
            mx = perf[t].get(scenario, {}).get("max")
            if not fixed or not mx:
                continue
            b_fixed = base.get(scenario, {}).get("fixed")
            b_max = base.get(scenario, {}).get("max")
            added = fixed["p99_ms"] - b_fixed["p99_ms"] if b_fixed and t != "direct" else None
            ratio = f"{mx['rps'] / b_max['rps'] * 100:.0f}%" if b_max and t != "direct" else "–"
            codes = ", ".join(f"{k}×{v}" for k, v in sorted(fixed["status_codes"].items()))
            # Below the requested rate the target is saturated: its "latency" is queueing time.
            if rate and fixed["rps"] < 0.95 * rate:
                codes += f" — **saturated** ({fixed['rps']:.0f} of {rate} req/s)"
            # A clean request that is not answered 200 was blocked: the row measures a deny.
            if scenario.startswith("clean") and set(fixed["status_codes"]) - {"200"}:
                codes += " — **blocked a clean request**"
            lines.append(f"| {LABELS.get(t, t)} | {fmt(fixed['p50_ms'])} | {fmt(fixed['p99_ms'])} | "
                         f"{fmt(fixed['p999_ms'])} | {fmt(added)} | {mx['rps']:.0f} | {ratio} | {codes} |")
        lines.append("")
    mem = [(t, perf[t]["memory"]) for t in ordered(perf) if "memory" in perf[t]]
    if mem:
        lines += ["## Memory after the load runs", "", "| Target | RSS |", "|---|---:|"]
        lines += [f"| {LABELS.get(t, t)} | {m} |" for t, m in mem]
        lines.append("")
    if gtw:
        targets = ordered(gtw)
        lines += ["## Detection (gotestwaf)", "",
                  "| Target | attacks blocked | legitimate passed | gotestwaf score |", "|---|---:|---:|---:|"]
        for t in targets:
            g = gtw[t]
            lines.append(f"| {LABELS.get(t, t)} | {g['tp_score']:.2f}% ({g['tp_blocked']}/{g['tp_sent']}) | "
                         f"{g['tn_score']:.2f}% ({g['tn_passed']}/{g['tn_sent']}) | {g['score']:.2f}% |")
        lines += ["", "### Attacks blocked, per test case", "",
                  "| Test case | " + " | ".join(LABELS.get(t, t) for t in targets) + " |",
                  "|---|" + "---:|" * len(targets)]
        all_cases = sorted({c for t in targets for c in gtw[t]["cases"]})
        for c in all_cases:
            cells = []
            for t in targets:
                r = gtw[t]["cases"].get(c)
                cells.append(f"{r['blocked']}/{r['sent']}" if r else "–")
            lines.append(f"| {c} | " + " | ".join(cells) + " |")
        lines.append("")
    return "\n".join(lines)


def main():
    run = Path(sys.argv[1])
    env = (run / "env.txt").read_text() if (run / "env.txt").exists() else ""
    perf = load_perf(run / "perf") if (run / "perf").exists() else {}
    gtw = load_gotestwaf(run / "gotestwaf") if (run / "gotestwaf").exists() else {}
    summary = {"env": parse_env(env), "perf": perf, "gotestwaf": gtw}
    (run / "summary.json").write_text(json.dumps(summary, indent=2))
    (run / "summary.md").write_text(render(env, perf, gtw))
    print((run / "summary.md").read_text())


if __name__ == "__main__":
    main()
