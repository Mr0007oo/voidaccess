# extractor — Phase 2 Entity Extraction Pipeline

Converts raw scraped text into structured, queryable intelligence records.

## Architecture

```
raw page text
      │
      ▼
┌─────────────────┐
│ regex_patterns  │  Fast, precise extraction of fixed-format entities
│                 │  (wallets, CVEs, IPs, emails, PGP keys, paste URLs)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     ner.py      │  Dictionary + heuristic *candidate generation* for named
│                 │  entities (malware, ransomware, threat actors; spaCy ORG).
│                 │  Acceptance is delegated to entity_shape (not a denylist).
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  llm_extract    │  LLM-assisted extraction (optional, runs only when
│                 │  regex/NER already found entities on the page)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  normalizer     │  Canonical normalisation + per-call dedup.  Name-type
│                 │  candidates pass the entity_shape gate; confidence is
│                 │  computed per entity (see confidence.py).  Upserts to DB.
└────────┬────────┘
         │
         ▼
   ExtractionResult
```

## Shape-aware validation & the gazetteer (not a denylist)

Name-type candidates (`THREAT_ACTOR_HANDLE`, `ORGANIZATION_NAME`,
`MALWARE_FAMILY`, `RANSOMWARE_GROUP`) are accepted only if they *plausibly have
the shape of the claimed entity type* or match a maintained known-good reference
set — the opposite of the old "reject if on an ever-growing denylist" approach,
which could only ever suppress strings someone had already seen.

- **`gazetteer.py`** — loads a bundled snapshot of public taxonomies (MITRE
  ATT&CK via MISP galaxy + MISP threat-actor / ransomware / malware clusters)
  from `data/threat_gazetteer.json`.  A match is a strong known-good signal.
- **`entity_shape.py`** — structural + linguistic checks: unusual capitalisation
  (CamelCase / ALLCAPS), embedded digits / leetspeak, separators, org suffixes,
  proper-noun structure, and a comprehensive English dictionary
  (`data/common_words_en.txt`) plus a security-domain lexicon
  (`data/domain_stopwords_en.txt`) to recognise ordinary language.  Returns a
  tier (`gazetteer` / `shape_strong` / `shape_ok` / `shape_weak` / `reject`) and
  a continuous plausibility score.
- **`confidence.py`** — computes a continuous per-entity confidence from real
  signals (validation strength, shape plausibility, context support, method
  prior); corroboration across independent sources is folded in at the batch cap
  stage (`pipeline.apply_entity_cap`).

Refresh the reference data with `python scripts/update_gazetteer.py` (clearnet
fetch of the public taxonomies + dictionary).  Extraction itself never fetches
anything at runtime — it reads only the committed snapshots, so results stay
offline and deterministic.  If a snapshot is missing, the shape checks degrade
gracefully rather than failing.

## Entity Types

| Type | Source | Example |
|---|---|---|
| `BITCOIN_ADDRESS` | regex | `bc1qxy2k...`, `1A1z...`, `3J98t...` |
| `ETHEREUM_ADDRESS` | regex | `0x742d35Cc...` |
| `MONERO_ADDRESS` | regex | `4...` (95 chars) |
| `ONION_URL` | regex | `http://xyz.onion/path` |
| `EMAIL_ADDRESS` | regex | `user@example.com` |
| `PGP_KEY_BLOCK` | regex | Full armored block or fingerprint |
| `CVE_NUMBER` | regex | `CVE-2024-12345` |
| `IP_ADDRESS` | regex | Public IPv4 only (RFC1918 excluded) |
| `PHONE_NUMBER` | regex | `+14155552671` |
| `PASTE_URL` | regex | `https://pastebin.com/abc123` |
| `THREAT_ACTOR_HANDLE` | NER | Context-detected username/alias |
| `MALWARE_FAMILY` | NER | `LockBit`, `Emotet`, `RedLine` |
| `RANSOMWARE_GROUP` | NER | `BlackCat`, `REvil`, `Conti` |
| `ORGANIZATION_NAME` | NER | orgs in threat context (spaCy) |

## Usage

```python
from extractor import extract_entities_from_page, extract_entities_from_pages

# Single page
result = await extract_entities_from_page(
    page_text="...",
    page_url="http://example.onion/page",
    page_id=42,
    investigation_id=7,
    llm=my_llm,           # optional
    run_llm_extraction=True,
)
print(result.entity_count, result.entities_by_type)

# Multiple pages (concurrent, semaphore-limited)
results = await extract_entities_from_pages(
    pages=[{"url": "...", "text": "..."}],
    max_concurrent=5,
)
```

## Dependencies

- `spacy` + `en_core_web_sm` model for organisation-name extraction
  - Install model: `python -m spacy download en_core_web_sm`
  - If the model is absent, NER falls back to dictionary + heuristics only
- `eth-utils` (+ `eth-hash[pycryptodome]`) for genuine EIP-55 Ethereum address
  checksum validation — an address written in valid checksummed form reaches the
  `checksum_verified` confidence tier, above `format_verified` for a shape-only
  (e.g. all-lowercase) match.  Full `web3` is accepted as a fallback if present;
  without any checksum library, ETH addresses degrade to `format_verified`.
- Reference data in `data/`: `threat_gazetteer.json`, `common_words_en.txt`,
  `domain_stopwords_en.txt` — regenerated by `scripts/update_gazetteer.py`
- All DB operations require `DATABASE_URL` to be set; without it, entities are
  extracted but not persisted

## Configuration

No new environment variables.  Uses the same `DATABASE_URL` and LLM
configuration (via `llm.py` / `llm_utils.py`) already present from Phase 1.
