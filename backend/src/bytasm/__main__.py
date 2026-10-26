"""Allow `python -m bytasm ...` as an alternative to the `bytasm` command."""

from bytasm.cli import main

raise SystemExit(main())
