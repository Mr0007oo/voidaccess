/**
 * TopoBackground — static SVG network-topology scene for the homepage.
 * Simulates a frozen entity-relationship graph: nodes (entities) connected
 * by edges (relationships), exactly what VoidAccess uncovers on the dark web.
 * No animations. No external deps. Pure SVG + CSS.
 */
export function TopoBackground() {
  // ── Node definitions ────────────────────────────────────────────────────
  // Coordinates are in a 1440×900 space. Nodes are kept away from the
  // viewport center (where the search box lives) so they frame the content.
  // hub: true → slightly larger, brighter, with a faint halo ring
  const nodes = [
    // Left spine
    { id: 0,  x:  68, y: 140, hub: false },
    { id: 1,  x:  42, y: 310, hub: false },
    { id: 2,  x:  95, y: 455, hub: true  },  // left hub
    { id: 3,  x:  52, y: 630, hub: false },
    { id: 4,  x:  88, y: 810, hub: false },
    // Right spine
    { id: 5,  x: 1375, y: 110, hub: false },
    { id: 6,  x: 1400, y: 290, hub: false },
    { id: 7,  x: 1355, y: 470, hub: true  },  // right hub
    { id: 8,  x: 1395, y: 660, hub: false },
    { id: 9,  x: 1360, y: 840, hub: false },
    // Top band
    { id: 10, x: 260,  y:  38, hub: false },
    { id: 11, x: 465,  y:  22, hub: false },
    { id: 12, x: 700,  y:  45, hub: false },
    { id: 13, x: 940,  y:  28, hub: false },
    { id: 14, x: 1160, y:  55, hub: false },
    // Bottom band
    { id: 15, x: 210,  y: 878, hub: false },
    { id: 16, x: 430,  y: 892, hub: false },
    { id: 17, x: 680,  y: 876, hub: false },
    { id: 18, x: 940,  y: 888, hub: false },
    { id: 19, x: 1195, y: 870, hub: false },
    // Inner-left cluster (frames search box left side)
    { id: 20, x: 200,  y: 195, hub: false },
    { id: 21, x: 285,  y: 360, hub: true  },  // inner-left hub
    { id: 22, x: 175,  y: 530, hub: false },
    { id: 23, x: 310,  y: 700, hub: false },
    // Inner-right cluster
    { id: 24, x: 1140, y: 210, hub: false },
    { id: 25, x: 1240, y: 385, hub: false },
    { id: 26, x: 1160, y: 560, hub: true  },  // inner-right hub
    { id: 27, x: 1225, y: 710, hub: false },
    // Sparse interior accents (subtle, low opacity)
    { id: 28, x: 400,  y: 155, hub: false },
    { id: 29, x: 1030, y: 740, hub: false },
  ];

  // ── Edge definitions ─────────────────────────────────────────────────────
  // Each pair [a, b] draws a line between node a and node b.
  // Chosen to look like an organic OSINT graph, not a grid.
  const edges: [number, number][] = [
    // Left spine connections
    [0, 1], [1, 2], [2, 3], [3, 4],
    // Right spine connections
    [5, 6], [6, 7], [7, 8], [8, 9],
    // Top band chain
    [10, 11], [11, 12], [12, 13], [13, 14],
    // Bottom band chain
    [15, 16], [16, 17], [17, 18], [18, 19],
    // Top-to-spines
    [0, 10], [5, 14],
    // Bottom-to-spines
    [4, 15], [9, 19],
    // Inner-left cluster
    [20, 21], [21, 22], [22, 23],
    // Inner-right cluster
    [24, 25], [25, 26], [26, 27],
    // Cross-connects: left spine ↔ inner-left
    [1, 20], [2, 21], [3, 22],
    // Cross-connects: right spine ↔ inner-right
    [6, 24], [7, 25], [8, 26],
    // Top band ↔ inner clusters
    [10, 20], [11, 28], [28, 20],
    [13, 24], [14, 24],
    // Bottom band ↔ inner clusters
    [15, 23], [16, 23],
    [18, 27], [19, 27],
    // Accent interior
    [28, 21], [29, 26],
    [12, 28],
    [17, 29],
  ];

  return (
    <div
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden"
      aria-hidden
    >
      {/* ── Base background ────────────────────────────────────────────── */}
      <div className="absolute inset-0" style={{ backgroundColor: "#080B11" }} />

      {/* ── SVG topology layer ─────────────────────────────────────────── */}
      <svg
        viewBox="0 0 1440 900"
        preserveAspectRatio="xMidYMid slice"
        className="absolute inset-0 h-full w-full"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Edge glow filter */}
          <filter id="edge-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="1.2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Hub node glow filter */}
          <filter id="hub-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          {/* Large corner atmosphere gradients */}
          <radialGradient id="atmos-tl" cx="0%" cy="0%" r="60%">
            <stop offset="0%"   stopColor="#1e3a5f" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#080B11" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="atmos-br" cx="100%" cy="100%" r="60%">
            <stop offset="0%"   stopColor="#1a2f50" stopOpacity="0.15" />
            <stop offset="100%" stopColor="#080B11" stopOpacity="0" />
          </radialGradient>
          {/* Hub halo gradient */}
          <radialGradient id="hub-halo" cx="50%" cy="50%" r="50%">
            <stop offset="0%"   stopColor="#58a6ff" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#58a6ff" stopOpacity="0"  />
          </radialGradient>
        </defs>

        {/* Atmospheric corner washes */}
        <rect x="0"   y="0"   width="1440" height="900" fill="url(#atmos-tl)" />
        <rect x="0"   y="0"   width="1440" height="900" fill="url(#atmos-br)" />

        {/* ── Edges ─────────────────────────────────────────────────── */}
        <g filter="url(#edge-glow)">
          {edges.map(([a, b]) => {
            const na = nodes[a];
            const nb = nodes[b];
            return (
              <line
                key={`e-${a}-${b}`}
                x1={na.x} y1={na.y}
                x2={nb.x} y2={nb.y}
                stroke="rgba(88,166,255,0.13)"
                strokeWidth="0.8"
              />
            );
          })}
        </g>

        {/* ── Hub halos ─────────────────────────────────────────────── */}
        {nodes.filter((n) => n.hub).map((n) => (
          <circle
            key={`halo-${n.id}`}
            cx={n.x} cy={n.y} r={28}
            fill="url(#hub-halo)"
          />
        ))}

        {/* ── Nodes ─────────────────────────────────────────────────── */}
        {nodes.map((n) =>
          n.hub ? (
            <g key={`n-${n.id}`} filter="url(#hub-glow)">
              {/* Outer ring */}
              <circle
                cx={n.x} cy={n.y} r={6}
                fill="none"
                stroke="rgba(88,166,255,0.35)"
                strokeWidth="1"
              />
              {/* Inner fill */}
              <circle
                cx={n.x} cy={n.y} r={3}
                fill="rgba(88,166,255,0.7)"
              />
            </g>
          ) : (
            <circle
              key={`n-${n.id}`}
              cx={n.x} cy={n.y} r={2}
              fill="rgba(88,166,255,0.38)"
            />
          )
        )}

        {/* ── Faint frozen "ping" rings around hub nodes ─────────────── */}
        {nodes.filter((n) => n.hub).map((n) => (
          <circle
            key={`ping-${n.id}`}
            cx={n.x} cy={n.y} r={18}
            fill="none"
            stroke="rgba(88,166,255,0.07)"
            strokeWidth="1"
          />
        ))}
      </svg>

      {/* ── Radial vignette — darkens edges, keeps center open ─────────── */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 65% at 50% 50%, transparent 0%, rgba(8,11,17,0.65) 80%, rgba(8,11,17,0.92) 100%)",
        }}
      />

      {/* ── Top & bottom edge fade ─────────────────────────────────────── */}
      <div
        className="absolute inset-x-0 top-0 h-32"
        style={{
          background: "linear-gradient(to bottom, rgba(8,11,17,0.7) 0%, transparent 100%)",
        }}
      />
      <div
        className="absolute inset-x-0 bottom-0 h-32"
        style={{
          background: "linear-gradient(to top, rgba(8,11,17,0.7) 0%, transparent 100%)",
        }}
      />
    </div>
  );
}
