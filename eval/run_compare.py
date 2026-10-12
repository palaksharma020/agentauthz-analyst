#!/usr/bin/env python3
"""Base vs fine-tuned vs fine-tuned+RAG evaluation against local Ollama (stdlib only).

  python3 eval/run_compare.py --heldout        # held-out eval.jsonl: base vs v1 vs v2 (cached per model)
  python3 eval/run_compare.py --three-tier     # Q1-Q3 + R1-R3 across all three tiers
"""
import argparse
import collections
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rag"))
from rag_pipeline import PLAIN_TEMPLATE, chat, guard, rag_answer  # noqa: E402

BASE = "llama3.2:3b"
FT = "agentauthz"
LABELS = ("ALLOW", "STEP_UP", "DENY")


def parse(text):
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            d = str(obj.get("decision", "")).upper().replace("-", "_").replace(" ", "_")
            return (d if d in LABELS else None), True, obj
        except json.JSONDecodeError:
            pass
    # Fall back to the first label word, so the base model is scored on intent, not formatting.
    m = re.search(r"\b(ALLOW|STEP[_ -]?UP|DENY)\b", text.upper())
    return (m.group(1).replace(" ", "_").replace("-", "_") if m else None), False, None


def macro_f1(pairs):
    f1s = []
    for lab in LABELS:
        tp = sum(1 for g, p in pairs if g == lab and p == lab)
        fp = sum(1 for g, p in pairs if g != lab and p == lab)
        fn = sum(1 for g, p in pairs if g == lab and p != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(f1s) / len(f1s)


CACHE = ROOT / "eval" / "results"


def heldout(n, models):
    rows = [json.loads(l) for l in (ROOT / "data" / "eval.jsonl").open()]
    rows = rows[:n] if n else rows
    results = {}
    CACHE.mkdir(exist_ok=True)
    for model in models:
        cache = CACHE / f"heldout_{model.replace(':', '_')}_{len(rows)}.json"
        if cache.exists():
            results[model] = tuple(json.loads(cache.read_text()))
            gcache = CACHE / f"heldout_{model.replace(':', '_')}+guard_{len(rows)}.json"
            if gcache.exists():
                results[model + " +guard"] = tuple(json.loads(gcache.read_text()))
            continue
        pairs, guarded, valid, by_src, t0 = [], [], 0, collections.defaultdict(lambda: [0, 0]), time.time()
        for i, r in enumerate(rows, 1):
            out = chat(model, r["messages"][1]["content"], r["messages"][0]["content"])
            pred, ok_json, obj = parse(out)
            valid += ok_json
            pairs.append((r["decision"], pred))
            if obj and "checks" in obj:
                guarded.append((r["decision"], guard(obj)[0]))
            else:
                guarded.append((r["decision"], pred))
            by_src[r["source"]][0] += pred == r["decision"]
            by_src[r["source"]][1] += 1
            print(f"\r{model:14s} {i}/{len(rows)}", end="", file=sys.stderr, flush=True)
        print(file=sys.stderr)
        acc = sum(g == p for g, p in pairs) / len(pairs)
        results[model] = (acc, macro_f1(pairs), valid / len(rows), dict(by_src), (time.time() - t0) / len(rows))
        cache.write_text(json.dumps(results[model]))
        if any(g != p for g, p in zip(guarded, pairs)):
            gacc = sum(g == p for g, p in guarded) / len(guarded)
            under = sum(1 for g, p in guarded if p in LABELS and g in LABELS and LABELS.index(p) < LABELS.index(g))
            results[model + " +guard"] = (gacc, macro_f1(guarded), valid / len(rows), {}, 0.0)
            (CACHE / f"heldout_{model.replace(':', '_')}+guard_{len(rows)}.json").write_text(  # noqa: E501
                json.dumps(results[model + " +guard"]))
            results[model + " +guard"] += (under,)
    srcs = sorted({r["source"] for r in rows})
    print(f"\nHeld-out evaluation: {len(rows)} events never seen in training")
    print("+guard = deterministic floor from the model's own checks (escalate-only)\n")
    head = f"{'model':18s}{'accuracy':>8s}{'macro-F1':>10s}{'valid JSON':>12s}" + "".join(f"{s:>22s}" for s in srcs) + f"{'s/event':>9s}"
    print(head)
    print("-" * len(head))
    for model, (acc, f1, vj, bs, spe) in results.items():
        cells = "".join(f"{bs[s][0]:>15d}/{bs[s][1]:<6d}" if s in bs else f"{'-':>22s}" for s in srcs)
        speed = f"{spe:>9.1f}" if spe else f"{'-':>9s}"
        print(f"{model:18s}{acc:>8.0%}{f1:>10.2f}{vj:>12.0%}{cells}{speed}")


def three_tier():
    """Same questions through base, fine-tuned (FT), FT + RAG; plus the deterministic guard on FT+RAG.

    For R1-R3 the FT tier is shown twice: on the bare event, and on the analyst's question + event.
    With the question but no retrieval, the model tends to *invent* a policy to answer it, so its
    uncited policy claims are printed as evidence of hallucination.
    """
    qs = json.loads((ROOT / "eval" / "questions.json").read_text())
    rq = json.loads((ROOT / "eval" / "rag_questions.json").read_text())
    rows = [(q["id"], q["title"], q["prompt"].split("EVENT:\n", 1)[1], None, q["expected"]["decision"]) for q in qs]
    rows += [(q["id"], q["title"], q["event"], q["chat_input"], q["expected_with_acme_policy"]["decision"]) for q in rq]
    mark = lambda p, exp: f"{p or '?'}{'✓' if p == exp else '✗'}"  # noqa: E731
    print(f"\n{'Q':4s}{'expected':>9s}{'base':>10s}{'FT':>10s}{'FT+Q':>10s}{'FT+RAG':>10s}{'+guard':>10s}  sources cited (FT+RAG)")
    print("-" * 100)
    notes = []
    for qid, title, event, chat_input, exp in rows:
        b, _, _ = parse(chat(BASE, PLAIN_TEMPLATE.format(event=event)))
        f, _, _ = parse(chat(FT, PLAIN_TEMPLATE.format(event=event)))
        fq = "-"
        if chat_input:
            fq, _, fobj = parse(chat(FT, PLAIN_TEMPLATE.format(event=chat_input)))
            claims = [r for r in (fobj or {}).get("reasons", []) if "polic" in r.lower() or "approved" in r.lower()]
            if claims and not (fobj or {}).get("sources"):
                notes.append(f"{qid} FT+Q (no retrieval) claimed: {claims[0]!r}, citing no source")
        out, hits = rag_answer(chat_input or event)
        r, _, obj = parse(out)
        g, fired = guard(obj) if obj else (r, [])
        srcs = ", ".join((obj or {}).get("sources", [])) or "(none cited)"
        fq_cell = mark(fq, exp) if fq != "-" else "-"
        print(f"{qid:4s}{exp:>9s}{mark(b, exp):>10s}{mark(f, exp):>10s}{fq_cell:>10s}{mark(r, exp):>10s}{mark(g, exp):>10s}  {srcs}")
        print(f"    {title}" + (f"   [guard fired: {', '.join(fired)}]" if g != r else ""))
    if notes:
        print("\nHallucinated policy without retrieval:")
        for n in notes:
            print("  - " + n)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--heldout", type=int, nargs="?", const=0, help="evaluate first N held-out rows (0 = all)")
    ap.add_argument("--three-tier", action="store_true")
    ap.add_argument("--report", action="store_true", help="print the saved summary (eval/results/summary.txt)")
    ap.add_argument("--models", default=f"{BASE},agentauthz-v1,{FT}", help="comma-separated Ollama models for --heldout")
    a = ap.parse_args()
    if a.heldout is not None:
        heldout(a.heldout, a.models.split(","))
    if a.three_tier:
        three_tier()
    if a.report:
        print((CACHE / "summary.txt").read_text())
    if a.heldout is None and not a.three_tier and not a.report:
        ap.print_help()
