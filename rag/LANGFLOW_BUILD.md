# Build the AgentAuthZ RAG flow in LangFlow Desktop

This takes about 20 minutes. Component names can differ slightly between LangFlow versions. If you can't find one, type its name in the **search box** at the top of the left Components sidebar. Ollama components may sit under **Models**, **Embeddings**, or a separate **Ollama** bundle.

**Prerequisites:**
- Ollama is running (llama icon in the menu bar).
- `ollama list` shows `agentauthz` and `nomic-embed-text`.

**Paths used below:**
- Corpus folder: `~/.langflow/data/agentauthz_corpus`
- Chroma folder: `~/.langflow/data/agentauthz_chroma`

Type them as absolute paths in LangFlow (for example `/Users/<you>/.langflow/data/agentauthz_corpus`); the `~` shorthand may not expand.

**Shortcut:** instead of building by hand, import `rag/langflow_agentauthz.json` (**My Projects → Upload/Import**) and replace `YOUR_USERNAME` in the Directory and Chroma DB path fields with your macOS user name.

> **Why not the repo folder?** LangFlow Desktop's Directory component may only read inside the server's working directory (`~/.langflow/data`). Anything else fails with *"Directory path escapes the allowed root"*, and symlinks are blocked. Copy the corpus there first, and re-run this after you edit `rag/corpus/`:
> ```bash
> rag/sync_corpus_to_langflow.sh   # run from the repo root
> ```

## Target flow

```
INGESTION (run once)
  [Directory] ──Data──▶ [Split Text] ──Chunks──▶ [Chroma DB: Ingest Data]
                                                   ▲
  [Ollama Embeddings] ─────────Embedding──────────┘

QUERY (every chat message)
  [Chat Input] ──Message──▶ [Chroma DB: Search Query] ──Search Results──▶ [Parser] ──▶ [Prompt {context}]
  [Chat Input] ──Message──────────────────────────────────────────────────────────────▶ [Prompt {event}]
  [Prompt] ──Prompt Message──▶ [Ollama (agentauthz)] ──Text/Message──▶ [Chat Output]
```
One Chroma DB component does both jobs: it ingests when built and searches when a query arrives.

## Steps

1. Click **+ New Flow → Blank Flow**. Rename it `AgentAuthZ RAG` (click the name at the top).
2. **Directory** (Data):
   - Path: the corpus folder above
   - Types: `md`
   - Recursive: off
3. **Split Text** (Processing):
   - Chunk Size `700`
   - Chunk Overlap `80`
   - Separator `\n`
   - Connect **Directory → Data** to **Split Text → Data / Input**.
4. **Ollama Embeddings** (Embeddings):
   - Base URL `http://localhost:11434`
   - Model `nomic-embed-text` (click the refresh ↻ icon if the dropdown is empty)
5. **Chroma DB** (Vector Stores):
   - Collection Name `acme_authz`
   - Persist Directory: the Chroma folder above
   - Number of Results `4`
   - Connect **Split Text → Chunks** to **Chroma → Ingest Data**.
   - Connect **Ollama Embeddings → Embedding** to **Chroma → Embedding**.
6. **Chat Input** (Input / Output). Connect **Chat Input → Message** to **Chroma → Search Query**.
7. **Parser** (Processing; older versions call it **Parse Data**):
   - Mode `Parser` or `Stringify` if asked
   - Template: `[source: {file_path}] {text}`
   - Separator `\n`
   - Connect **Chroma → Search Results** to **Parser → Data / Input**.
8. **Prompt** (Prompts, or **Prompt Template**). Paste this template exactly:
   ```
   Assess this event and return the authorization decision as JSON. Use the CONTEXT (retrieved policy) when relevant and list the files you used in "sources".

   CONTEXT:
   {context}

   EVENT:
   {event}
   ```
   Two input handles appear: `context` and `event`.
   - Connect **Parser → Parsed Text** to **Prompt → context**.
   - Connect **Chat Input → Message** to **Prompt → event**. One output can feed two inputs.
9. **Ollama** (Models / Language Models):
   - Base URL `http://localhost:11434`
   - Model Name `agentauthz` (click ↻ to refresh)
   - Temperature `0`
   - In **Controls** or advanced settings, set **System Message** to:
     ```
     You are AgentAuthZ, an identity security analyst. You receive one authentication or authorization event: either a human login or an AI agent acting on behalf of a user (OAuth token exchange / MCP tool call). Return ONLY a JSON object with keys in this order: checks (result of each security check on the event), decision (ALLOW | STEP_UP | DENY), risk (0-100), reasons (list of short strings), controls (standards or controls applied), and sources (files used) when CONTEXT is provided.
     ```
   - Connect **Prompt → Prompt Message** to **Ollama → Input**.
10. **Chat Output**. Connect **Ollama → Text / Message** to **Chat Output → Text / Inputs**.
11. **Ingest once:** click ▶ (Run component) on **Chroma DB**. When it shows a green check, the corpus is embedded and the `agentauthz_chroma/` folder appears.
12. **Test:** open **Playground** (top right). Paste the full R1 block from `eval/questions.md` (the question line plus `EVENT: {...}`). Expect `"decision": "DENY"` with `acme_agent_registry.md` in `sources`.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Model dropdown is empty | Make sure Ollama is running and the Base URL is `http://localhost:11434`, then click ↻ |
| Answer has no `sources` / wrong decision | Open Parser output (click the component's output inspector). Is the Acme chunk there? If not, raise Number of Results to `6`. |
| "Directory path escapes the allowed root" | Directory Path must be `~/.langflow/data/agentauthz_corpus`. Run `rag/sync_corpus_to_langflow.sh` first. |
| Chroma error "dimension mismatch" | Delete `~/.langflow/data/agentauthz_chroma` and run step 11 again |
| `{file_path}` shows blank | Change the Parser template to `[source: {source}] {text}` or `{data}`. Paste the Parser output into chat and I'll adjust. |
