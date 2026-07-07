# Changelog

All notable changes to VoidAccess are documented here.

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
