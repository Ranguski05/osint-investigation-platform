/**
 * Purely decorative backdrop for the investigation graph viewport: a faint
 * wireframe globe suggesting a network/intelligence-dashboard environment.
 *
 * This is NOT part of the graph -- it renders behind the (now transparent)
 * ForceGraph3D canvas as a plain SVG image, with no data of its own. It
 * carries no geographic data, no investigation entities, and no
 * interactivity (`pointer-events: none` throughout), so it can never be
 * confused with real graph content and never intercepts clicks/hover.
 *
 * Deliberately plain 2D SVG rather than a second Three.js scene: it needs
 * to stay fixed regardless of how the graph's camera moves, never affect
 * zoomToFit's bounding-box math, and cost effectively nothing to render.
 */
export function GlobeBackdrop() {
  return (
    <svg
      className="globe-backdrop"
      viewBox="0 0 600 600"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <radialGradient id="globeAtmosphere" cx="50%" cy="50%" r="50%">
          <stop offset="55%" stopColor="#5ec8f8" stopOpacity="0" />
          <stop offset="82%" stopColor="#5ec8f8" stopOpacity="0.1" />
          <stop offset="100%" stopColor="#5ec8f8" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="globeBody" cx="42%" cy="38%" r="70%">
          <stop offset="0%" stopColor="#16233b" />
          <stop offset="70%" stopColor="#0c1524" />
          <stop offset="100%" stopColor="#070c16" />
        </radialGradient>
        <filter id="globeSoftBlur" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="10" />
        </filter>
        <clipPath id="globeClip">
          <circle cx="300" cy="300" r="238" />
        </clipPath>
      </defs>

      {/* Starfield -- a handful of faint fixed points, well outside the globe disc. */}
      <g fill="#cfe4ff">
        <circle cx="60" cy="90" r="1.1" opacity="0.35" />
        <circle cx="120" cy="500" r="1" opacity="0.25" />
        <circle cx="500" cy="70" r="1.3" opacity="0.3" />
        <circle cx="545" cy="150" r="0.9" opacity="0.4" />
        <circle cx="40" cy="330" r="1" opacity="0.3" />
        <circle cx="560" cy="420" r="1.2" opacity="0.25" />
        <circle cx="90" cy="200" r="0.8" opacity="0.35" />
        <circle cx="480" cy="540" r="1" opacity="0.3" />
        <circle cx="30" cy="450" r="1.1" opacity="0.2" />
        <circle cx="520" cy="480" r="0.9" opacity="0.3" />
      </g>

      {/* Outer atmospheric glow, extending past the globe's own edge. */}
      <circle cx="300" cy="300" r="300" fill="url(#globeAtmosphere)" />

      {/* Globe body. */}
      <circle cx="300" cy="300" r="238" fill="url(#globeBody)" stroke="rgba(148, 197, 255, 0.22)" strokeWidth="1" />

      <g clipPath="url(#globeClip)">
        {/* Extremely faint terrain-like mottling -- abstract soft blobs, not a real map. */}
        <g opacity="0.05" filter="url(#globeSoftBlur)" fill="#7fd1ae">
          <ellipse cx="230" cy="230" rx="70" ry="40" />
          <ellipse cx="380" cy="260" rx="55" ry="30" />
          <ellipse cx="300" cy="400" rx="90" ry="35" />
          <ellipse cx="180" cy="380" rx="40" ry="25" />
        </g>

        {/* Longitude meridians. */}
        <g fill="none" stroke="rgba(148, 197, 255, 0.10)" strokeWidth="1">
          <ellipse cx="300" cy="300" rx="195" ry="238" />
          <ellipse cx="300" cy="300" rx="130" ry="238" />
          <ellipse cx="300" cy="300" rx="65" ry="238" />
        </g>

        {/* Latitude bands. */}
        <g fill="none" stroke="rgba(148, 197, 255, 0.10)" strokeWidth="1">
          <ellipse cx="300" cy="300" rx="238" ry="28" />
          <ellipse cx="300" cy="240" rx="232" ry="26" />
          <ellipse cx="300" cy="360" rx="232" ry="26" />
          <ellipse cx="300" cy="180" rx="208" ry="22" />
          <ellipse cx="300" cy="420" rx="208" ry="22" />
          <ellipse cx="300" cy="122" rx="159" ry="16" />
          <ellipse cx="300" cy="478" rx="159" ry="16" />
        </g>
      </g>

      {/* Thin bright rim light on the globe's own edge, for a touch of depth. */}
      <circle cx="300" cy="300" r="238" fill="none" stroke="rgba(94, 200, 248, 0.12)" strokeWidth="1.5" />
    </svg>
  );
}
