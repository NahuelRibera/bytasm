"""Pinned capa CLI entry with a private rule-cache directory on every platform.

capa 10 ignores XDG_CACHE_HOME on macOS. Direct its cache-directory function
only for this child invocation, then call the real CLI main with unchanged
arguments/output. Never consult a user/global pickled rule cache.
"""

from importlib.metadata import version
from pathlib import Path


def main() -> int:
    if version("flare-capa") != "10.0.0":
        return 1
    import capa.main  # type: ignore[import-untyped]
    import capa.rules.cache  # type: ignore[import-untyped]

    cache = Path("cache")
    if cache.is_symlink() or not cache.is_dir():
        return 1
    cache = cache.resolve()
    original = capa.rules.cache.get_default_cache_directory
    capa.rules.cache.get_default_cache_directory = lambda: cache
    try:
        return int(capa.main.main() or 0)
    finally:
        capa.rules.cache.get_default_cache_directory = original


if __name__ == "__main__":
    raise SystemExit(main())
