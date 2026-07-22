# Changelog

All notable changes to VoidAccess are documented here.

## [Unreleased]
### Added
- Five new free (key-optional) intelligence sources, each reporting honestly into `sources_used`:
  - **XposedOrNot** (`sources/breach_lookup.py`) — email breach-exposure lookup, complements HIBP with a different corpus; free tier includes stealer-log exposure.
  - **LeakCheck** public tier (`sources/breach_lookup.py`) — breach-source corroboration; an email surfacing in both XposedOrNot and LeakCheck is tagged `breach_corroborated`.
  - **Hudson Rock Cavalier** (`sources/infostealer.py`) — infostealer intelligence (30M+ malware-infected machines) queried by email AND domain; one of the few sources giving domain-level infostealer exposure.
  - **NVD 2.0** (`sources/nvd.py`) — full CVE metadata (CVSS, CWE, description, dates) for any extracted CVE, complementing CISA KEV's actively-exploited subset. Optional `NVD_API_KEY` raises the rate limit.
  - **ransomlook.io** (`sources/enrichment.py`) — second ransomware-group tracker that cross-validates ransomware.live; shared leak-site `.onion` seeds are URL-normalised to dedup across the two trackers.
- First pytest test suite (`tests/`), covering the parsers for the five new sources with mocked HTTP (`aioresponses`).

### Fixed
- Phase-A threat-intel enrichment now preserves the results of sources that finished before the deadline instead of discarding the entire batch when the 59s/55s cap is hit (`_gather_with_partial_results`).
- CLI `investigate` reputation steps (domain/hash/email) no longer clobber the threaded `extraction_results` list into a `(results, stats)` tuple, which had silently starved subsequent steps and actor-profile aggregation of entities.
- Typed relationship edges. A distinct LLM relationship-extraction pass (`extractor/relationship_extract.py`) runs after entity extraction and asks, for the entities already found on a page, which specific typed relationship (if any) connects them — `USED`, `DROPS`, `CONTROLS`, `TARGETS`, `EXPLOITS`, `COMMUNICATES_WITH`. Each relationship carries its own claim confidence, separate from the confidence of the two entities it connects. The vocabulary is bounded: anything the LLM cannot map cleanly is dropped and the pair keeps its plain co-occurrence edge.
- The pass is additive — co-occurrence edge generation is unchanged; typed edges sit alongside it. Bounded by `MAX_REL_PAGES_PER_INV` (default 10; one LLM call per selected page) so it can never scale unbounded with page count, mirroring the existing `MAX_LLM_PAGES_PER_INV` entity-extraction cap. Disable with `ENABLE_RELATIONSHIP_EXTRACTION=false`.

### Fixed
- STIX export keyed its entity→object map only by raw entity value, so graph edges whose node id is disambiguated (e.g. `THREAT_ACTOR_HANDLE` as `handle@forum`) were silently dropped from the bundle. The map now also registers the graph node id, so relationships with a threat-actor endpoint — including the new typed relationships — survive into the bundle.

### Changed
- STIX `Relationship` SROs now carry the edge's confidence (STIX 2.1 `confidence`, 0–100), and the new typed edge types map to documented STIX relationship types (`uses`, `drops`, `targets`, `exploits`, `communicates-with`); `CONTROLS` has no standard STIX verb and degrades to `related-to`. `CO_INVESTIGATION` now has an explicit mapping instead of relying on the default.

## [1.7.2] - 2026-07-08
### Fixed
- STIX relationship generation now avoids near-quadratic same-page edge explosions by emitting bounded semantic co-occurrence edges instead of every pair on a page.
- Persistent relationship loading now skips malformed non-UUID endpoints before graph hydration, preventing UUID coercion crashes during STIX export.
- THREAT_ACTOR_HANDLE and ORGANIZATION_NAME NER noise from repeated audits is filtered before persistence, including the confirmed generic security/programming vocabulary false positives.
- MISP, Sigma, API, and shared DB query paths now use explicit SQLAlchemy select constructs instead of passing subquery objects into `.in_()`.
- Optional configuration warnings are summarized once per process instead of printing a repeated warning wall.
- Refined query persistence now strips labelled/chatty LLM responses down to the actual short search query.

### Changed
- Tor result-count variance was reassessed as environmental network/search-engine flakiness for this pass; no code change was made for that item.

## [1.7.1] - 2026-07-07
### Fixed
- STIX export was silently producing an empty 82-byte bundle (regression from 1.6.3's working fix); now produces real bundles with entities and relationships
- Entity extraction quality had regressed on queries containing CVE/financial terms, returning only organization-name noise; CVE extraction now works correctly
- Confidence scores were clustered at 1-2 discrete values across an entire investigation; now show genuine multi-value spread reflecting source quality, extraction method, and corroboration
- Source-quality scoring (previously claimed but not actually implemented) is now genuinely present on extracted entities and contributes to confidence
- Fixed a CLI readback bug where entities were successfully extracted and persisted but the final displayed/exported count could read as zero, because the query only checked direct investigation_id matches and ignored entities linked via InvestigationEntityLink
- Fixed duplicate canonical entities appearing in results when the same entity existed in both the direct-match and linked-match branches of the entity query; results are now deduped after the union, not before

### Known Issues
- corroborating_sources field still not populated (carried over from 1.6.4, tracked separately)

## [1.7.0] - 2026-07-07
### Fixed
- --version now works as a top-level flag
- config.json now written with 0600 permissions
- Entities from Tor/.onion pages now persist to the entity store
- RFC 5737/2606 placeholder IPs/domains/emails filtered or flagged instead of treated as high-confidence threat intel
- Source-quality scoring added for low-trust sources (GitHub README docs)
- Stale OPENROUTER_API_KEY warning fixed
- Stuck 'running' investigation rows now cleaned up
- DATE entity extraction capped
- IOC package email export no longer drops emails
- STIX export SQLAlchemy warning fixed
- Non-interactive `voidaccess configure` input now detected and handled

### Changed
- sentence-transformers, torch, transformers, telethon, playwright moved to optional extras (`voidaccess[nlp]`, `[telegram]`, `[js]`, `[all]`)
- Added VOIDACCESS_NO_BANNER for session-level banner suppression

### Known Issues
- corroborating_sources not populated for any entity (tracked for next release)
- LLM may under-tag malware names present in summary but not in structured extraction

## [1.6.4] - 2026-07-07
### Fixed
- STIX relationship export now declares and installs its graph dependency, and export commands visibly warn when relationships cannot be built.
- Added missing third-party dependency declarations for imported libraries across the codebase.
- Entity store `corroborating_sources` field is silently null for all entities because `merge_with_db` in `extractor/normalizer.py` never calls `update_entity_source_count` after the initial upsert. Every entity — from tor_search, RSS, GitHub, or enrichment — has `source_count=1` and `corroborating_sources=null` instead of the source name (e.g. `["tor_search"]`). Fix requires calling `update_entity_source_count` in `merge_with_db` after each upsert, passing the page's source label derived from the page URL. Tracked as a separate fix cycle — do not treat as a footnote.

## [1.6.3] - 2026-07-07
### Fixed
- LLM entity extraction no longer streams raw JSON fragments to stdout during investigations with LLM enabled.
- STIX export no longer writes an empty bundle silently when `stix2` is missing; `stix2` is now a declared dependency and the export produces a real bundle.
- `click` is now a declared dependency, so the first-run spaCy model download triggered by `voidaccess configure` no longer fails silently and leave NER disabled.
- `use_proxies` and `use_proxy` config flags have been renamed to `rest_api_transport_enabled` and `residential_proxy_enabled`, with automatic migration for existing config files and a fix for BOM-prefixed JSON loading.

### Known Issues
- (Resolved in v1.6.4) Entity extraction and persistence from Tor/.onion pages is now confirmed working end-to-end.

## [1.6.2] - 2026-07-03
### Added
- Clarified the final release state after the residential proxy fallback QA pass and the `--use-scraping-api` transport reintroduction.
- Confirmed the six live-verified safety guarantees from the verification arc, including silent fallback behavior when proxy credentials are invalid.

### Fixed
- Residential proxy credential handling and release metadata alignment.

## [1.6.0] - 2026-07-02
### Added
- Optional clearnet ScrapingAnt integration for paste sites and RSS feeds.
- Three independent ScrapingAnt products are now documented and supported separately: Web Scraping API, Residential Proxy transport, and Datacenter Proxy transport.
- Web Scraping API transport uses `VOIDACCESS_USE_PROXIES=true` and `SCRAPINGANT_API_KEY`.
- Residential Proxy transport uses `VOIDACCESS_USE_PROXY=true` with `SCRAPINGANT_PROXY_USERNAME` and `SCRAPINGANT_PROXY_PASSWORD`.
- Datacenter Proxy transport is configured with `SCRAPINGANT_PROXY_TYPE=datacenter` and the same proxy credentials, but live verification is still open.
- The transport selection model is mutually exclusive per request; if both transports are enabled, the proxy transport wins for that request and the chokepoint logs the choice once.
- Tor, `.onion`, GitHub, and GitLab traffic remain unaffected by the integration.

### Fixed
- Corrected earlier documentation and configuration drift that conflated the Web Scraping API credential with the proxy credentials and described the wrong host model.
- Clarified that there is no chained transport mode.
