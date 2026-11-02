// The Journey landscape (M2, recomposed in M2.1): the approved muerte rider on a near ridge at the
// right, a small distant gothic settlement in the middle ground, a restrained dithered moon with a
// broken astrolabe halo above its skyline, fog layered behind the rider (never over it).
// Hierarchy, strongest first: rider, copy, settlement, moon and halo, binary texture.
// Original artwork composed here from architectural primitives (towers with set-back belfries
// and corner pinnacles, gabled houses, a buttressed nave, a broken wall); nothing is traced.
// Everything is decorative: aria-hidden, hidden when atmosphere is reduced, no data inside.
import { BinaryField, mulberry32 } from "./binaryField";

const W = 1200;
const H = 420;
const GROUND = 322;
const MOON = { x: 714, y: 150, r: 23 };
// The rider stands on the outcrop: feet on the ridge line, scythe tip below the top edge.
const RIDER = { x: 900, y: 36, h: 352 };
const RIDER_W = (RIDER.h * 1130) / 1448;

type Path = string[];
const n = (value: number) => Math.round(value * 10) / 10;
// Bodies standing on the ground run below it, so the hill always covers their foot.
const rect = (p: Path, x: number, top: number, w: number, bottom: number) =>
  p.push(`M${n(x)} ${n(top)}H${n(x + w)}V${n(bottom >= GROUND - 8 ? GROUND + 40 : bottom)}H${n(x)}Z`);
const tri = (p: Path, x: number, base: number, w: number, h: number) =>
  p.push(`M${n(x)} ${n(base)}L${n(x + w / 2)} ${n(base - h)}L${n(x + w)} ${n(base)}Z`);

/** A finial: a hairline mast ending in a small lozenge (no cross: the city is not a church map). */
function finial(p: Path, cx: number, tip: number) {
  rect(p, cx - 0.5, tip - 8, 1, tip + 1);
  p.push(`M${n(cx)} ${n(tip - 12)}L${n(cx + 1.8)} ${n(tip - 9)}L${n(cx)} ${n(tip - 6)}L${n(cx - 1.8)} ${n(tip - 9)}Z`);
}

/** A tower whose upper stage sets back, with corner pinnacles and a spire. */
function spireTower(p: Path, cx: number, w: number, h: number, spire: number, base = GROUND) {
  const lower = base - h * 0.68;
  const top = base - h;
  rect(p, cx - w / 2, lower, w, base);
  const upper = w * 0.78;
  rect(p, cx - upper / 2, top, upper, lower + 1);
  // Corner pinnacles on the set-back and at the belfry top.
  for (const side of [-1, 1]) {
    const px = cx + side * (w / 2) - (side > 0 ? 3 : 0);
    rect(p, px, lower - 6, 3, lower + 1);
    tri(p, px - 0.5, lower - 6, 4, 9);
    const qx = cx + side * (upper / 2) - (side > 0 ? 2.4 : 0);
    tri(p, qx - 0.4, top + 0.5, 3.2, spire * 0.26);
  }
  tri(p, cx - upper * 0.36, top + 0.5, upper * 0.72, spire);
  finial(p, cx, top - spire);
}

function gableHouse(p: Path, x: number, w: number, h: number, roof: number, base = GROUND) {
  rect(p, x, base - h, w, base);
  tri(p, x - 1, base - h + 0.5, w + 2, roof);
}

/** A long nave with a pitched roof and a row of buttress pinnacles. */
function nave(p: Path, x0: number, x1: number, h: number, roof: number, base = GROUND) {
  const top = base - h;
  rect(p, x0, top, x1 - x0, base);
  p.push(`M${n(x0)} ${n(top + 0.5)}L${n(x0 + 6)} ${n(top - roof)}H${n(x1 - 6)}L${n(x1)} ${n(top + 0.5)}Z`);
  for (let x = x0 + 4; x < x1 - 4; x += 13) {
    rect(p, x, top - 10, 3, top + 8);
    tri(p, x - 0.6, top - 10, 4.2, 9);
  }
}

/** A ruined wall: an irregular broken top with a gap, from a seeded sequence. */
function ruin(p: Path, x0: number, x1: number, h: number, seed: number, base = GROUND) {
  const random = mulberry32(seed);
  let d = `M${n(x0)} ${n(base)}`;
  for (let x = x0; x <= x1; x += 3 + random() * 5) {
    const broken = random() < 0.18 ? h * 0.35 : h * (0.7 + random() * 0.3);
    d += `L${n(x)} ${n(base - broken)}`;
  }
  p.push(`${d}L${n(x1)} ${n(base + 40)}L${n(x0)} ${n(base + 40)}Z`);
}

/** A ridge line from a seeded walk between control heights, closed to the bottom of the scene. */
function ridge(points: Array<[number, number]>, seed: number, roughness: number): string {
  const random = mulberry32(seed);
  let d = `M${points[0]![0]} ${H}L${points[0]![0]} ${points[0]![1]}`;
  for (let index = 1; index < points.length; index += 1) {
    const [x0, y0] = points[index - 1]!;
    const [x1, y1] = points[index]!;
    const steps = Math.max(2, Math.round((x1 - x0) / 9));
    for (let step = 1; step <= steps; step += 1) {
      const t = step / steps;
      const eased = t * t * (3 - 2 * t);
      const jitter = step === steps ? 0 : (random() - 0.5) * roughness;
      d += `L${n(x0 + (x1 - x0) * t)} ${n(y0 + (y1 - y0) * eased + jitter)}`;
    }
  }
  return `${d}L${points[points.length - 1]![0]} ${H}Z`;
}

function buildCity(): string {
  const p: Path = [];
  // Left: the broken outer wall and a split watchtower.
  ruin(p, 548, 640, 22, 7);
  rect(p, 592, GROUND - 44, 13, GROUND);
  ruin(p, 590, 607, 10, 11, GROUND - 42);
  // Lower town: steep gables climbing toward the cathedral.
  gableHouse(p, 640, 15, 18, 13);
  gableHouse(p, 653, 12, 26, 15);
  gableHouse(p, 667, 18, 21, 12);
  spireTower(p, 694, 15, 66, 46);
  gableHouse(p, 705, 16, 30, 14);
  // The cathedral: twin west towers, facade gable, buttressed nave, crossing spire, apse.
  spireTower(p, 742, 19, 98, 74);
  spireTower(p, 776, 19, 98, 74);
  rect(p, 750, GROUND - 70, 18, GROUND);
  tri(p, 749, GROUND - 69.5, 20, 22);
  nave(p, 785, 882, 56, 16);
  spireTower(p, 834, 13, 84, 104, GROUND - 4);
  gableHouse(p, 882, 22, 44, 18);
  rect(p, 890, GROUND - 58, 5, GROUND - 40);
  tri(p, 889.4, GROUND - 58, 6.2, 12);
  // Right: a second parish, roofs and a far bell tower fading toward the road.
  gableHouse(p, 905, 14, 24, 13);
  spireTower(p, 928, 14, 60, 40);
  gableHouse(p, 940, 18, 20, 12);
  gableHouse(p, 957, 12, 15, 10);
  spireTower(p, 980, 10, 46, 30);
  ruin(p, 986, 1040, 14, 23);
  return p.join("");
}

/** A fainter back row of roofs and towers, for depth behind the cathedral. */
function buildBackCity(): string {
  const p: Path = [];
  const base = GROUND - 6;
  spireTower(p, 628, 11, 52, 30, base);
  gableHouse(p, 660, 26, 34, 14, base);
  spireTower(p, 716, 12, 74, 44, base);
  nave(p, 724, 770, 48, 12, base);
  spireTower(p, 806, 10, 92, 52, base);
  gableHouse(p, 862, 30, 52, 16, base);
  spireTower(p, 902, 12, 78, 50, base);
  nave(p, 910, 972, 40, 10, base);
  spireTower(p, 958, 9, 58, 34, base);
  gableHouse(p, 996, 24, 30, 12, base);
  return p.join("");
}

const CITY = buildCity();
const BACK_CITY = buildBackCity();
// The settlement sits far back on the ridge: small, raised toward the horizon, its base under the hill.
const CITY_SCALE = `translate(690 ${GROUND - 22}) scale(0.7) translate(-790 -${GROUND})`;
const FAR_RIDGE = ridge([[0, 352], [160, 336], [300, 318], [380, 300], [470, 262], [560, 284], [640, 240], [720, 270], [880, 246], [990, 272], [1080, 236], [1200, 262]], 3, 5);
const HILL = ridge([[0, 404], [220, 392], [380, 368], [440, 334], [468, GROUND + 3], [1112, GROUND + 4], [1160, 336], [1200, 344]], 5, 3);
const MID_ROCKS = ridge([[0, 420], [300, 416], [420, 392], [560, 380], [700, 388], [820, 368], [900, 376], [1200, 360]], 9, 7);
const OUTCROP = ridge([[836, 420], [884, 402], [924, 389], [990, 383], [1070, 381], [1140, 385], [1200, 379]], 13, 4);
const WINDOWS: Array<[number, number, number]> = [
  [742, GROUND - 60, 5],
  [776, GROUND - 60, 5],
  [694, GROUND - 40, 4],
  [834, GROUND - 52, 4],
  [928, GROUND - 34, 4],
  [662, GROUND - 14, 3],
  [911, GROUND - 13, 3],
];
// No star near the rider: celestial marks stay over the settlement and the open sky.
const STARS: Array<[number, number, number]> = [
  [612, 58, 4],
  [846, 74, 3.5],
  [560, 128, 2.5],
  [668, 196, 2],
  [808, 168, 2],
];

function Star({ x, y, size }: { x: number; y: number; size: number }) {
  const s = size;
  const k = s * 0.18;
  return <path className="scene-star" d={`M${x} ${y - s}L${x + k} ${y - k}L${x + s} ${y}L${x + k} ${y + k}L${x} ${y + s}L${x - k} ${y + k}L${x - s} ${y}L${x - k} ${y - k}Z`} />;
}

export function JourneyScene() {
  return (
    <div className="journey-scene atmo" aria-hidden="true">
      <BinaryField className="journey-field" light={{ x: 0.62, y: 0.32, radius: 0.09 }} clearLeft={0.36} fadeBottom={0.5} density={0.5} />
      <svg className="journey-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMaxYMax slice" focusable="false">
        <defs>
          {/* A pale, desaturated moon: violet only at the limb, like the engraved boards. */}
          <radialGradient id="jy-moon" cx="38%" cy="34%" r="72%">
            <stop offset="0" stopColor="#e6e1ea" />
            <stop offset="0.38" stopColor="#b2a8c2" />
            <stop offset="0.78" stopColor="#6c5f88" />
            <stop offset="1" stopColor="#2e2541" />
          </radialGradient>
          <radialGradient id="jy-moon-glow">
            <stop offset="0" stopColor="#9c86c8" stopOpacity="0.22" />
            <stop offset="0.5" stopColor="#6b3fb0" stopOpacity="0.07" />
            <stop offset="1" stopColor="#6b3fb0" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="jy-terminator" cx="74%" cy="72%" r="78%">
            <stop offset="0" stopColor="#fff" stopOpacity="1" />
            <stop offset="0.5" stopColor="#fff" stopOpacity="0.6" />
            <stop offset="1" stopColor="#fff" stopOpacity="0.08" />
          </radialGradient>
          <mask id="jy-dither-mask">
            <circle cx={MOON.x} cy={MOON.y} r={MOON.r} fill="url(#jy-terminator)" />
          </mask>
          <pattern id="jy-dots" width="2.2" height="2.2" patternUnits="userSpaceOnUse">
            <circle cx="1.1" cy="1.1" r="0.66" fill="#0f0a1a" />
          </pattern>
          <pattern id="jy-hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(-38)">
            <path d="M0 2H4" stroke="#efebe4" strokeWidth="0.45" strokeOpacity="0.07" />
          </pattern>
          <pattern id="jy-hatch-h" width="5" height="3" patternUnits="userSpaceOnUse">
            <path d="M0 1.5H5" stroke="#efebe4" strokeWidth="0.4" strokeOpacity="0.05" />
          </pattern>
          <linearGradient id="jy-rim" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#b9a6dc" stopOpacity="0.2" />
            <stop offset="0.45" stopColor="#d9cdef" stopOpacity="0.7" />
            <stop offset="1" stopColor="#8a6cc0" stopOpacity="0.08" />
          </linearGradient>
          <linearGradient id="jy-road" x1="0" y1="1" x2="0" y2="0">
            <stop offset="0" stopColor="#d9cdef" stopOpacity="0.12" />
            <stop offset="1" stopColor="#d9cdef" stopOpacity="0.015" />
          </linearGradient>
          {/* The rider's tone: bone-white head and shoulders, sinking to violet at the hooves. */}
          <linearGradient id="jy-rider-tone" gradientUnits="userSpaceOnUse" x1="0" y1={RIDER.y} x2="0" y2={RIDER.y + RIDER.h}>
            <stop offset="0" stopColor="#f6f1ea" />
            <stop offset="0.42" stopColor="#ddd5e8" />
            <stop offset="0.78" stopColor="#ab96d4" />
            <stop offset="1" stopColor="#7d5cc0" />
          </linearGradient>
          <mask id="jy-rider-mask" maskUnits="userSpaceOnUse" x={RIDER.x} y={RIDER.y} width={RIDER_W} height={RIDER.h} style={{ maskType: "alpha" }}>
            <image href="/art/chars/muerte.cutout.png" x={RIDER.x} y={RIDER.y} width={RIDER_W} height={RIDER.h} preserveAspectRatio="xMidYMid meet" />
          </mask>
          <filter id="jy-blur" x="-20%" y="-50%" width="140%" height="200%">
            <feGaussianBlur stdDeviation="9" />
          </filter>
          <filter id="jy-soft" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="26" />
          </filter>
        </defs>

        {/* Sky: a restrained moon and a broken astrolabe halo above the settlement. */}
        <circle cx={MOON.x} cy={MOON.y} r={MOON.r * 4.2} fill="url(#jy-moon-glow)" />
        <g className="scene-halo" fill="none" stroke="#b9a6dc">
          <circle cx={MOON.x} cy={MOON.y} r={MOON.r + 12} strokeWidth="0.6" strokeOpacity="0.32" strokeDasharray="70 9 24 16 40 6" />
          <circle cx={MOON.x} cy={MOON.y} r={MOON.r + 26} strokeWidth="4" strokeOpacity="0.16" strokeDasharray="0.55 4.6" />
          <circle cx={MOON.x} cy={MOON.y} r={MOON.r + 29} strokeWidth="0.45" strokeOpacity="0.14" strokeDasharray="120 40 30 60" />
          <circle cx={MOON.x} cy={MOON.y} r={MOON.r + 58} strokeWidth="0.5" strokeOpacity="0.2" strokeDasharray="150 360" transform={`rotate(-150 ${MOON.x} ${MOON.y})`} />
          <circle cx={MOON.x} cy={MOON.y} r={MOON.r + 74} strokeWidth="0.4" strokeOpacity="0.1" strokeDasharray="2 7 50 14" />
          {[0, 90, 180, 270].map((angle) => (
            <line
              key={angle}
              x1={MOON.x}
              y1={MOON.y - MOON.r - 34}
              x2={MOON.x}
              y2={MOON.y - MOON.r - 44}
              strokeWidth="0.7"
              strokeOpacity="0.36"
              transform={`rotate(${angle + 12} ${MOON.x} ${MOON.y})`}
            />
          ))}
          <rect x={MOON.x - 2} y={MOON.y - MOON.r - 28} width="4" height="4" transform={`rotate(45 ${MOON.x} ${MOON.y - MOON.r - 26})`} fill="#07050c" strokeWidth="0.7" strokeOpacity="0.5" />
        </g>
        <circle cx={MOON.x} cy={MOON.y} r={MOON.r} fill="url(#jy-moon)" opacity="0.86" />
        <g fill="#3b2d58" fillOpacity="0.32">
          <ellipse cx={MOON.x - 7} cy={MOON.y - 5} rx="4.5" ry="3.2" />
          <ellipse cx={MOON.x + 6} cy={MOON.y + 8} rx="5.5" ry="3.6" />
          <ellipse cx={MOON.x + 9} cy={MOON.y - 9} rx="2.6" ry="2" />
          <ellipse cx={MOON.x - 4} cy={MOON.y + 12} rx="2.2" ry="1.6" />
        </g>
        <rect x={MOON.x - MOON.r} y={MOON.y - MOON.r} width={MOON.r * 2} height={MOON.r * 2} fill="url(#jy-dots)" mask="url(#jy-dither-mask)" />
        {STARS.map(([x, y, size]) => (
          <Star key={`${x}-${y}`} x={x} y={y} size={size} />
        ))}

        {/* Far mountains, then the distant settlement under haze: low contrast, soft rim. */}
        <path d={FAR_RIDGE} fill="#100c18" />
        <path d={FAR_RIDGE} fill="url(#jy-hatch-h)" />
        {/* Horizon haze: the sky lightens behind the settlement so its dark silhouette reads at a distance. */}
        <ellipse cx="700" cy={GROUND - 40} rx="330" ry="62" fill="#5d4e7c" fillOpacity="0.34" filter="url(#jy-soft)" />
        <ellipse cx="700" cy={GROUND - 26} rx="250" ry="30" fill="#7d6c9c" fillOpacity="0.22" filter="url(#jy-blur)" />
        <g className="scene-city" transform={CITY_SCALE}>
          <path d={BACK_CITY} fill="#2a2338" opacity="0.85" />
          <path d={BACK_CITY} fill="url(#jy-hatch)" />
          <path d={CITY} fill="url(#jy-rim)" transform="translate(-1.1 -1.1)" opacity="0.55" />
          <path d={CITY} fill="#0e0b15" />
          <path d={CITY} fill="url(#jy-hatch)" />
          <circle cx="759" cy={GROUND - 54} r="4.2" fill="none" stroke="#b9a6dc" strokeOpacity="0.32" strokeWidth="0.8" />
          {WINDOWS.slice(0, 4).map(([x, y, h]) => (
            <rect key={`${x}-${y}`} x={x - 0.9} y={y} width="1.8" height={h} rx="0.9" fill="#c9b8ea" fillOpacity="0.4" />
          ))}
        </g>
        <ellipse className="scene-fog scene-fog-far" cx="700" cy={GROUND - 12} rx="330" ry="20" fill="#8c80a6" fillOpacity="0.16" filter="url(#jy-blur)" />
        <path d={HILL} fill="#09080e" />
        <path d={HILL} fill="url(#jy-hatch)" />
        <ellipse className="scene-fog scene-fog-mid" cx="640" cy="342" rx="420" ry="16" fill="#8c80a6" fillOpacity="0.12" filter="url(#jy-blur)" />

        {/* The road leaves the rider's ridge and winds back to the settlement's gate. */}
        <path
          d="M1060 420C1004 404 948 392 900 378C852 364 812 350 772 334C750 325 734 316 720 306L726 306C742 315 760 324 782 333C824 349 866 362 914 375C966 389 1024 402 1100 420Z"
          fill="url(#jy-road)"
        />
        <path d={MID_ROCKS} fill="#060509" />
        <path d={MID_ROCKS} fill="url(#jy-hatch-h)" />

        {/* Local contrast: a shadow pool behind the rider separates it from sky, halo and field. */}
        <ellipse cx={RIDER.x + RIDER_W * 0.52} cy={RIDER.y + RIDER.h * 0.5} rx={RIDER_W * 0.62} ry={RIDER.h * 0.56} fill="#040306" fillOpacity="0.78" filter="url(#jy-soft)" />
        <path d={OUTCROP} fill="url(#jy-rim)" transform="translate(-1 -1.2)" opacity="0.4" />
        <path d={OUTCROP} fill="#050407" />
        <path d={OUTCROP} fill="url(#jy-hatch-h)" />
        <g className="scene-rider">
          <rect x={RIDER.x} y={RIDER.y} width={RIDER_W} height={RIDER.h} fill="url(#jy-rider-tone)" mask="url(#jy-rider-mask)" />
        </g>
        <ellipse className="scene-fog scene-fog-near" cx="480" cy="416" rx="460" ry="20" fill="#6d55a0" fillOpacity="0.12" filter="url(#jy-blur)" />
      </svg>
      {/* Marks the placement for tests and the character map; the rider itself is drawn in the SVG. */}
      <span className="journey-rider" data-character="muerte" />
    </div>
  );
}
