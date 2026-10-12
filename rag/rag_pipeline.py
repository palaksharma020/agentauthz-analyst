#!/usr/bin/env python3
"""Code-based reference RAG pipeline (stdlib only), mirroring the LangFlow flow.

  corpus/*.md --split by section--> nomic-embed-text --> JSON vector index
  event --embed--> cosine top-k --> CONTEXT block --> agentauthz (Ollama) --> JSON decision + sources

Usage:
  python3 rag/rag_pipeline.py --build                 # (re)index rag/corpus
  python3 rag/rag_pipeline.py --event '<event json>'  # ask through the full pipeline
  python3 rag/rag_pipeline.py --question R1           # one of eval/rag_questions.json
"""
import argparse
import json
import math
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "rag" / "corpus"
INDEX = ROOT / "rag" / ".index.json"
OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = "nomic-embed-text"
CHAT_MODEL = os.environ.get("AGENTAUTHZ_MODEL", "agentauthz")
TOP_K = 4

# Prompts come from the dataset builder so serving always matches the training format.
sys.path.insert(0, str(ROOT / "data"))
from build_dataset import CTX_TEMPLATE, SYSTEM_PROMPT  # noqa: E402
from build_dataset import USER_TEMPLATE as PLAIN_TEMPLATE  # noqa: E402


def _post(path, payload, timeout=300):
    req = urllib.request.Request(f"{OLLAMA}{path}", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def embed(texts):
    return _post("/api/embed", {"model": EMBED_MODEL, "input": texts})["embeddings"]


def chat(model, user, system=SYSTEM_PROMPT):
    out = _post("/api/chat", {"model": model, "stream": False, "options": {"temperature": 0, "num_ctx": 4096},
                              "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
    return out["message"]["content"].strip()


def chunk_markdown(path):
    """One chunk per '## ' section, prefixed with the document title for context."""
    text = path.read_text()
    title = text.splitlines()[0].lstrip("# ").strip()
    parts = re.split(r"\n(?=## )", text)
    chunks = []
    for p in parts:
        body = " ".join(p.split())
        if len(body) > 40:
            chunks.append({"source": path.name, "text": f"{title}. {body}" if not p.startswith("# ") else body})
    return chunks


def build_index():
    chunks = [c for f in sorted(CORPUS.glob("*.md")) for c in chunk_markdown(f)]
    vecs = embed([f"search_document: {c['text']}" for c in chunks])
    for c, v in zip(chunks, vecs):
        c["vec"] = v
    INDEX.write_text(json.dumps(chunks))
    print(f"indexed {len(chunks)} chunks from {len(list(CORPUS.glob('*.md')))} files -> {INDEX.name}")
    return chunks


def _cos(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)) + 1e-9)


def retrieve(query, k=TOP_K):
    chunks = json.loads(INDEX.read_text()) if INDEX.exists() else build_index()
    q = embed([f"search_query: {query}"])[0]
    ranked = sorted(chunks, key=lambda c: -_cos(q, c["vec"]))
    return ranked[:k]


RANK = {"ALLOW": 0, "STEP_UP": 1, "DENY": 2}


def guard(answer):
    """Deterministic floor derived from the model's own `checks`: it can only escalate, never relax.

    The LLM extracts and explains; code enforces the non-negotiable rules. This catches cases
    where the model reports a failing check but still under-decides (e.g. q4 quantization slips).
    Returns (decision, triggered_rules).
    """
    c = answer.get("checks") or {}
    deny = [k for k, bad in [
        ("agent_registered", c.get("agent_registered") is False),
        ("agent_status", c.get("agent_status") not in (None, "active")),
        ("act_claim", c.get("act_claim") in ("missing", "mismatch")),
        ("audience", c.get("audience") == "mismatch"),
        ("scopes_within_delegation", c.get("scopes_within_delegation") is False),
        ("user_entitled", c.get("user_entitled") is False),
        ("token_replay", c.get("token_replay") is True),
        ("token_age_ok", c.get("token_age_ok") is False),
        ("chain_depth_ok", c.get("chain_depth_ok") is False),
        ("ip_reputation", c.get("ip_reputation") == "known_attack_source"),
    ] if bad]
    step = [k for k, bad in [
        ("irreversible_unapproved", c.get("irreversible_unapproved") is True),
        ("bulk_sensitive", c.get("bulk_sensitive") is True),
        ("geo", c.get("geo") == "anomalous"),
        ("hour_ok", c.get("hour_ok") is False),
        ("mfa_fresh", c.get("mfa_fresh") is False),
    ] if bad]
    floor = "DENY" if deny else "STEP_UP" if step else "ALLOW"
    llm = str(answer.get("decision", "DENY")).upper()  # unparseable decision -> fail closed
    llm = llm if llm in RANK else "DENY"
    return (llm if RANK[llm] >= RANK[floor] else floor), deny + step


def rag_answer(event, model=CHAT_MODEL, k=TOP_K):
    hits = retrieve(event, k)
    context = "\n".join(f"[source: {h['source']}] {h['text'][:900]}" for h in hits)
    return chat(model, CTX_TEMPLATE.format(context=context, event=event)), hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--event")
    ap.add_argument("--question", help="R1/R2/R3 from eval/rag_questions.json")
    args = ap.parse_args()
    if args.build:
        build_index()
    event = args.event
    if args.question:
        qs = {q["id"]: q for q in json.loads((ROOT / "eval" / "rag_questions.json").read_text())}
        event = qs[args.question]["chat_input"]
        print(f"{args.question}: {qs[args.question]['title']}")
    if event:
        answer, hits = rag_answer(event)
        print("retrieved:", ", ".join(f"{h['source']}" for h in hits))
        print(answer)


if __name__ == "__main__":
    main()
