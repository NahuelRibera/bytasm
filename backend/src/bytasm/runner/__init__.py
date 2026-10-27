"""Run one adapter in a separate, resource-limited child process (blueprint 5.4.1).

This is process and resource separation for robustness: a parser crash, hang,
or runaway memory/CPU/output use ends one child process, not the API or CLI.
It is NOT a security sandbox. The child runs as the same user, with the same
filesystem view and network access as its parent. The input policy (fixture
manifest) is what keeps untrusted files away from the parser.

`bytasm.runner.child` is imported inside the child before any parsing library,
so this package's `__init__` must stay free of heavy imports.
"""
