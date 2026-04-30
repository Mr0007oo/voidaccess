"use client";

import { useEffect, useState, useCallback } from "react";
import { getMitreUrl, getCveUrl } from "@/lib/utils/entityLinks";
import { formatRelativeTime } from "@/lib/utils/formatRelativeTime";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface SelectedNodeData {
  id: string;
  label?: string;
  vaCategory?: string;
  color?: string;
  origColor?: string;
  // From GraphNodeJSON / raw attrs
  raw?: {
    id: string;
    type: string;
    confidence?: number;
    first_seen?: string | null;
    last_seen?: string | null;
    source_urls?: string[];
    metadata?: Record<string, unknown>;
  };
  // Extra enriched attrs possibly on graph node
  freshness_tag?: string;
  freshness_label?: string;
  freshness_color?: string;
  source_count?: number;
  corroborating_sources?: string[];
  context_snippet?: string;
  context?: string;
  // degree computed externally
  degree?: number;
}

interface EnrichedEntityData {
  id: string;
  entity_type: string;
  value: string;
  canonical_value?: string | null;
  confidence: number;
  context?: string | null;
  context_snippet?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  source_count?: number;
  corroborating_sources?: string[];
  freshness_tag?: string;
  freshness_label?: string;
  freshness_color?: string;
  metadata?: Record<string, unknown>;
}

interface NodeDetailPanelProps {
  node: SelectedNodeData | null;
  onClose: () => void;
  onIsolateNeighbors: (nodeId: string) => void;
}

// ─── Helper: Category label ────────────────────────────────────────────────────

const CAT_LABELS: Record<string, string> = {
  THREAT_ACTOR: "Threat Actor",
  WALLET:       "Wallet",
  MALWARE:      "Malware",
  FORUM:        "Forum",
  C2_SERVER:    "C2 Server",
  CVE:          "CVE",
  PASTE_URL:    "Paste URL",
  ONION_URL:    "Onion URL",
  EMAIL:        "Email",
  PGP_KEY:      "PGP Key",
  OTHER:        "Other",
};

// ─── Freshness indicator ────────────────────────────────────────────────────────

function FreshnessIndicator({ tag, label }: { tag?: string; label?: string }) {
  const dot = tag === "fresh"   ? "🟢"
            : tag === "recent"  ? "🟡"
            : tag === "aged"    ? "🟠"
            : tag === "stale"   ? "🔴"
            : "⚪";
  const text = label ?? (tag ? tag.charAt(0).toUpperCase() + tag.slice(1) : "Unknown");
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span>{dot}</span>
      <span style={{ color: "rgba(255,255,255,0.75)", fontSize: 12 }}>{text}</span>
    </span>
  );
}

// ─── Confidence bar ────────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = value >= 0.8 ? "#4ade80" : value >= 0.6 ? "#facc15" : "#f87171";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <span
        style={{
          display: "inline-block",
          width: 80,
          height: 6,
          borderRadius: 3,
          background: "rgba(255,255,255,0.08)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <span
          style={{
            display: "block",
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 3,
            transition: "width 0.4s ease",
          }}
        />
      </span>
      <span style={{ fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace", fontSize: 11, color: "rgba(255,255,255,0.7)" }}>
        {value.toFixed(2)}
      </span>
    </span>
  );
}

// ─── Main panel component ──────────────────────────────────────────────────────

export function NodeDetailPanel({ node, onClose, onIsolateNeighbors }: NodeDetailPanelProps) {
  const [enriched, setEnriched] = useState<EnrichedEntityData | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const visible = node !== null;

  // Reset enriched data when node changes
  useEffect(() => {
    if (!node) { setEnriched(null); setFetchError(null); return; }
    setEnriched(null);
    setFetchError(null);

    // Try to fetch full entity data from API
    const entityId = node.id;
    setLoading(true);
    const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    fetch(`${apiBase}/api/entities/${encodeURIComponent(entityId)}`, {
      credentials: "include",
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json() as Promise<EnrichedEntityData>;
      })
      .then((d) => { setEnriched(d); setFetchError(null); })
      .catch((err) => { setFetchError(String(err)); })
      .finally(() => setLoading(false));
  }, [node?.id]);

  const handleCopy = useCallback(() => {
    if (!node) return;
    // Use canonical value from enriched if available, otherwise node id
    const val = enriched?.canonical_value ?? enriched?.value ?? node.id;
    navigator.clipboard.writeText(val).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {/* ok */});
  }, [node, enriched]);

  // Merge attrs: prefer enriched API data, fall back to graph node attrs
  const entityType = enriched?.entity_type ?? node?.raw?.type ?? node?.vaCategory ?? "OTHER";
  const catLabel   = CAT_LABELS[node?.vaCategory ?? "OTHER"] ?? "Other";
  const dotColor   = node?.origColor ?? node?.color ?? "#4a5260";
  const displayVal = enriched?.canonical_value ?? enriched?.value ?? node?.id ?? "";
  const confidence = enriched?.confidence ?? node?.raw?.confidence ?? 0;
  const freshnessTag   = enriched?.freshness_tag   ?? node?.freshness_tag;
  const freshnessLabel = enriched?.freshness_label ?? node?.freshness_label;
  const sourceCount    = enriched?.source_count    ?? node?.source_count;
  const sources        = enriched?.corroborating_sources ?? node?.corroborating_sources ?? [];
  const contextText    = enriched?.context_snippet ?? enriched?.context ?? node?.context_snippet ?? node?.context;
  const firstSeen      = enriched?.first_seen ?? node?.raw?.first_seen;
  const lastSeen       = enriched?.last_seen  ?? node?.raw?.last_seen;

  // Enrichment links
  const isMitre  = entityType === "MITRE_TECHNIQUE";
  const isCve    = entityType === "CVE" || entityType === "CVE_NUMBER";
  const isIp     = entityType === "IP_ADDRESS";
  const shodanUrl = isIp ? `https://www.shodan.io/host/${encodeURIComponent(displayVal)}` : null;
  const mitreUrl  = isMitre ? getMitreUrl(displayVal) : null;
  const cveUrl    = isCve   ? getCveUrl(displayVal) : null;

  const panelStyle: React.CSSProperties = {
    position: "absolute",
    left: 0,
    top: 0,
    bottom: 0,
    width: 320,
    zIndex: 50,
    display: "flex",
    flexDirection: "column",
    background: "rgba(8, 11, 17, 0.97)",
    borderRight: "1px solid rgba(59, 130, 246, 0.18)",
    backdropFilter: "blur(16px)",
    transform: visible ? "translateX(0)" : "translateX(-100%)",
    transition: "transform 0.28s cubic-bezier(0.4, 0, 0.2, 1)",
    overflow: "hidden",
    pointerEvents: visible ? "auto" : "none",
  };

  const sectionStyle: React.CSSProperties = {
    padding: "10px 16px",
    borderBottom: "1px solid rgba(255,255,255,0.06)",
  };

  const sectionTitleStyle: React.CSSProperties = {
    fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
    fontSize: 9,
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    color: "rgba(255,255,255,0.35)",
    marginBottom: 8,
  };

  const rowStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 6,
  };

  const labelStyle: React.CSSProperties = {
    fontFamily: "'Inter', sans-serif",
    fontSize: 11,
    color: "rgba(255,255,255,0.45)",
  };

  const valueStyle: React.CSSProperties = {
    fontFamily: "'Inter', sans-serif",
    fontSize: 12,
    color: "rgba(255,255,255,0.82)",
  };

  return (
    <div style={panelStyle} aria-hidden={!visible}>
      {/* Header — Back button */}
      <div
        style={{
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid rgba(255,255,255,0.07)",
          flexShrink: 0,
        }}
      >
        <button
          onClick={onClose}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            background: "transparent",
            border: "none",
            cursor: "pointer",
            fontFamily: "'IBM Plex Mono', monospace",
            fontSize: 10,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "rgba(255,255,255,0.45)",
            padding: "2px 0",
            transition: "color 0.15s",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.color = "rgba(255,255,255,0.85)")}
          onMouseLeave={(e) => (e.currentTarget.style.color = "rgba(255,255,255,0.45)")}
        >
          ← Back to list
        </button>
        {loading && (
          <div
            style={{
              width: 12,
              height: 12,
              borderRadius: "50%",
              border: "2px solid rgba(88,166,255,0.3)",
              borderTopColor: "#58a6ff",
              animation: "spin 0.8s linear infinite",
            }}
          />
        )}
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>

        {/* Identity section */}
        <div style={{ padding: "16px 16px 12px" }}>
          {/* Type badge */}
          <div style={{ marginBottom: 10 }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
                padding: "2px 8px",
                borderRadius: 4,
                background: `${dotColor}20`,
                border: `1px solid ${dotColor}55`,
              }}
            >
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: dotColor, display: "inline-block" }} />
              <span
                style={{
                  fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
                  fontSize: 9,
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color: dotColor,
                }}
              >
                {catLabel}
              </span>
            </span>
          </div>

          {/* Value (full canonical) */}
          <div
            style={{
              fontFamily: "'JetBrains Mono', 'IBM Plex Mono', monospace",
              fontSize: 12,
              color: "rgba(255,255,255,0.9)",
              wordBreak: "break-all",
              lineHeight: 1.5,
              marginBottom: 10,
              padding: "8px 10px",
              background: "rgba(255,255,255,0.04)",
              borderRadius: 5,
              border: "1px solid rgba(255,255,255,0.07)",
              maxHeight: 90,
              overflowY: "auto",
            }}
          >
            {displayVal || node?.id}
          </div>

          {/* Copy button */}
          <button
            onClick={handleCopy}
            style={{
              width: "100%",
              padding: "5px 0",
              borderRadius: 4,
              border: "1px solid rgba(255,255,255,0.12)",
              background: copied ? "rgba(74,222,128,0.12)" : "rgba(255,255,255,0.04)",
              cursor: "pointer",
              fontFamily: "'IBM Plex Mono', monospace",
              fontSize: 10,
              letterSpacing: "0.08em",
              color: copied ? "#4ade80" : "rgba(255,255,255,0.55)",
              transition: "all 0.2s",
            }}
          >
            {copied ? "✓ Copied" : "Copy value"}
          </button>
        </div>

        {/* Intelligence section */}
        <div style={sectionStyle}>
          <div style={sectionTitleStyle}>Intelligence</div>

          {confidence > 0 && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Confidence</span>
              <ConfidenceBar value={confidence} />
            </div>
          )}

          {(freshnessTag || freshnessLabel) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Freshness</span>
              <FreshnessIndicator tag={freshnessTag} label={freshnessLabel} />
            </div>
          )}

          {(sourceCount !== undefined || sources.length > 0) && (
            <div style={{ ...rowStyle, marginBottom: 8 }}>
              <span style={labelStyle}>Sources</span>
              <span style={valueStyle}>
                {sourceCount ?? sources.length}
                {sources.length > 0 && (
                  <span style={{ color: "rgba(255,255,255,0.4)", marginLeft: 6 }}>
                    ({sources.slice(0, 3).join(" · ")})
                  </span>
                )}
              </span>
            </div>
          )}

          {firstSeen && (
            <div style={{ ...rowStyle, marginBottom: 6 }}>
              <span style={labelStyle}>First seen</span>
              <span style={valueStyle}>{formatRelativeTime(firstSeen)}</span>
            </div>
          )}

          {lastSeen && (
            <div style={{ ...rowStyle, marginBottom: 0 }}>
              <span style={labelStyle}>Last seen</span>
              <span style={valueStyle}>{formatRelativeTime(lastSeen)}</span>
            </div>
          )}
        </div>

        {/* Context section */}
        {contextText && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Context</div>
            <div
              style={{
                fontFamily: "'Inter', sans-serif",
                fontSize: 11,
                color: "rgba(255,255,255,0.6)",
                lineHeight: 1.6,
                fontStyle: "italic",
                padding: "8px 10px",
                background: "rgba(255,255,255,0.03)",
                borderRadius: 4,
                border: "1px solid rgba(255,255,255,0.06)",
                maxHeight: 100,
                overflowY: "auto",
              }}
            >
              "{contextText}"
            </div>
          </div>
        )}

        {/* Connections section */}
        {node && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Connections</div>
            <div style={{ ...rowStyle, flexDirection: "column", alignItems: "flex-start", gap: 8 }}>
              {node.degree !== undefined && node.degree > 0 && (
                <span style={{ ...valueStyle, fontSize: 11 }}>
                  Connected to <strong style={{ color: "rgba(255,255,255,0.9)" }}>{node.degree}</strong> other{" "}
                  {node.degree === 1 ? "entity" : "entities"}
                </span>
              )}
              <button
                onClick={() => { onIsolateNeighbors(node.id); onClose(); }}
                style={{
                  padding: "5px 10px",
                  borderRadius: 4,
                  border: "1px solid rgba(88,166,255,0.3)",
                  background: "rgba(88,166,255,0.07)",
                  cursor: "pointer",
                  fontFamily: "'IBM Plex Mono', monospace",
                  fontSize: 10,
                  letterSpacing: "0.07em",
                  color: "rgba(88,166,255,0.9)",
                  transition: "all 0.15s",
                  whiteSpace: "nowrap",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(88,166,255,0.14)";
                  e.currentTarget.style.borderColor = "rgba(88,166,255,0.6)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(88,166,255,0.07)";
                  e.currentTarget.style.borderColor = "rgba(88,166,255,0.3)";
                }}
              >
                View neighbors only
              </button>
            </div>
          </div>
        )}

        {/* Enrichment section */}
        {(isMitre || isCve || isIp) && (
          <div style={sectionStyle}>
            <div style={sectionTitleStyle}>Enrichment</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {isMitre && mitreUrl && (
                <a
                  href={mitreUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#f0a050",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(240,160,80,0.25)",
                    background: "rgba(240,160,80,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(240,160,80,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(240,160,80,0.06)"; }}
                >
                  → View on ATT&CK
                </a>
              )}
              {isCve && cveUrl && (
                <a
                  href={cveUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#e5c07b",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(229,192,123,0.25)",
                    background: "rgba(229,192,123,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(229,192,123,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(229,192,123,0.06)"; }}
                >
                  → View on NVD
                </a>
              )}
              {isIp && shodanUrl && (
                <a
                  href={shodanUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontFamily: "'IBM Plex Mono', monospace",
                    fontSize: 11,
                    color: "#56b6c2",
                    textDecoration: "none",
                    padding: "4px 8px",
                    borderRadius: 4,
                    border: "1px solid rgba(86,182,194,0.25)",
                    background: "rgba(86,182,194,0.06)",
                    transition: "all 0.15s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(86,182,194,0.12)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(86,182,194,0.06)"; }}
                >
                  → View on Shodan
                </a>
              )}
            </div>
          </div>
        )}

        {/* API error notice */}
        {fetchError && (
          <div style={{ padding: "8px 16px" }}>
            <span
              style={{
                fontFamily: "'IBM Plex Mono', monospace",
                fontSize: 9,
                color: "rgba(248,113,113,0.6)",
              }}
            >
              Note: Could not load full entity data
            </span>
          </div>
        )}

        {/* Bottom padding */}
        <div style={{ height: 24 }} />
      </div>

      {/* Spin keyframe injected via style tag — avoids CSS file dependency */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
