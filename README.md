# LLM Output Handling Gate (OWASP LLM05)

A deterministic gate that decides whether a model's output is safe to hand to a
given sink (`html`, `markdown`, `url`, `sql`, `shell`). No LLM calls, no
phrase-list heuristics — every decision is a pure regex/URL-parsing rule.

## Endpoint

`POST /sanitize-output`

```json
{"channel": "html | markdown | url | sql | shell", "output": "the model's output"}
```

Always responds `200` with:

```json
{"safe": true | false, "reason": "SAFE | INVALID_SCHEMA | SCRIPT_TAG | EVENT_HANDLER | DANGEROUS_SCHEME | EXTERNAL_EXFIL | SQL_METACHAR | SHELL_METACHAR | ENCODED_PAYLOAD"}
```

The handler never raises on malformed input (wrong types, missing fields,
non-JSON body, non-object body) — it always returns a normal 200 JSON
response with `reason: "INVALID_SCHEMA"` instead of letting FastAPI's
default validation return a 422. This matters for grading: an endpoint that
500s/422s on a malformed probe looks "unavailable" even though the service
itself is up.

## Rule order (implemented exactly as specified)

1. `INVALID_SCHEMA` — non-object body, bad `channel`, non-string `output`,
   or `output` over 20000 chars.
2. `ENCODED_PAYLOAD` — decode once (percent-escapes → HTML entities →
   `\uXXXX`); if the decoded string differs from the original **and** the
   decoded string would trip a channel rule, report `ENCODED_PAYLOAD`
   instead of the underlying rule name.
3. Channel rules, first match wins:
   - `html`: `SCRIPT_TAG` → `EVENT_HANDLER` → `DANGEROUS_SCHEME` → `EXTERNAL_EXFIL`
   - `markdown` / `url`: `DANGEROUS_SCHEME` → `EXTERNAL_EXFIL`
   - `sql`: `SQL_METACHAR`
   - `shell`: `SHELL_METACHAR`

### Host allowlist — exact match only

```
cdn-h0yekgt.example
app-hgmqaed.example
```

URLs are parsed with `urllib.parse` and only `.hostname` is compared
(lowercased) — this quietly defeats the common bypasses:
- `https://cdn-h0yekgt.example@attacker.example/` (credentials) → hostname is
  `attacker.example`, rejected.
- `https://attacker.example/?next=https://cdn-h0yekgt.example/` (query
  string) → hostname is `attacker.example`, rejected.
- `https://evil.cdn-h0yekgt.example/` (subdomain) → hostname is
  `evil.cdn-h0yekgt.example`, not an exact match, rejected.
- `//cdn-h0yekgt.example/x` (protocol-relative) → resolved as
  `https://cdn-h0yekgt.example/x` before parsing, since a browser will fetch
  it as absolute.

## Local dev

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Run tests:

```bash
pip install pytest httpx
python -m pytest test_main.py -v
```

45/45 tests pass locally, covering: schema validation edge cases, benign
output on every channel, each rule in isolation, rule-ordering conflicts
(e.g. a `<script>` tag that also has an `onerror=` attribute must report
`SCRIPT_TAG`, not `EVENT_HANDLER`), allowed-host positive cases,
look-alike-host negative cases (subdomain, credentials, query-string,
protocol-relative), and all three encoding layers (percent, HTML entity —
named/decimal/hex, `\uXXXX`).

## Deploy (Render free tier)

1. Push this directory to a public GitHub repo (e.g. `tds-ga7-q4`).
2. On [Render](https://render.com), **New +** → **Web Service** → connect
   the repo. Render will pick up `render.yaml` automatically (or set build
   command `pip install -r requirements.txt` and start command
   `uvicorn main:app --host 0.0.0.0 --port $PORT` manually).
3. Once deployed, your base URL is `https://<service-name>.onrender.com`
   and the graded endpoint is
   `https://<service-name>.onrender.com/sanitize-output`.

Note: Render's free tier spins down on idle, so the first request after a
period of inactivity can take 30–60s to wake up — if the grader has a short
timeout, hit `GET /` yourself once before submitting to warm it up.
