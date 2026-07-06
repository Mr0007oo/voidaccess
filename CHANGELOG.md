# Changelog

All notable changes to VoidAccess are documented here.

## [1.6.3] - 2026-07-07
### Fixed
- LLM entity extraction no longer streams raw JSON fragments to stdout during investigations with LLM enabled.
- STIX export no longer writes an empty bundle silently when `stix2` is missing; `stix2` is now a declared dependency and the export produces a real bundle.
- `click` is now a declared dependency, so the first-run spaCy model download triggered by `voidaccess configure` no longer fails silently and leave NER disabled.
- `use_proxies` and `use_proxy` config flags have been renamed to `rest_api_transport_enabled` and `residential_proxy_enabled`, with automatic migration for existing config files and a fix for BOM-prefixed JSON loading.

### Known Issues
- Entities extracted from Tor/.onion-scraped pages are not yet persisted to the entity store. The LLM summary correctly references `.onion` content, but structured entities from those pages are still missing and will be addressed in a follow-up release.

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
