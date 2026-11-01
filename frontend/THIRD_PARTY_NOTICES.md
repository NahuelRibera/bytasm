# Third-party notices (frontend bundle)

The built UI (`frontend/dist`) bundles these fonts. They are served from Bytasm's own
origin; no font is fetched from a third-party host.

| Component | Version | Source package | License |
|---|---|---|---|
| Inter (variable, Latin subset) | 4.x via Fontsource 5.3.0 | `@fontsource-variable/inter` | SIL Open Font License 1.1 |
| JetBrains Mono (variable, Latin subset) | 2.x via Fontsource 5.3.0 | `@fontsource-variable/jetbrains-mono` | SIL Open Font License 1.1 |

The full license texts ship with the packages
(`node_modules/@fontsource-variable/*/LICENSE`).

The character art masks in `public/art/chars/` are derived by `scripts/build_ascii_art.py`
from Bytasm's own ASCII character artwork; see `docs/design/ASCII_INTEGRATION.md`.
