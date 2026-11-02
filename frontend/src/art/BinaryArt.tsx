// Decorative character art (docs/design/ASCII_INTEGRATION.md). The image is a generated alpha
// mask (scripts/build_ascii_art.py); its colour comes from CSS, so one file serves every tint.
// Never placed inside a panel that shows sample data, and hidden when atmosphere is reduced.
import type { CharacterName } from "./characters";

export type ArtVariant = "cutout" | "field";
export type ArtTint = "ink" | "signal" | "ash" | "ghost" | "moonlit" | "bone";

export function BinaryArt({
  character,
  variant = "cutout",
  tint = "ink",
  className,
}: {
  character: CharacterName;
  variant?: ArtVariant;
  tint?: ArtTint;
  className?: string;
}) {
  const classes = ["binary-art", `art-${character}-${variant}`, `art-tint-${tint}`, className]
    .filter(Boolean)
    .join(" ");
  return <div className={classes} aria-hidden="true" data-character={character} />;
}
