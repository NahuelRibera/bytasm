"""Test-only server for the Playwright suite's self_built scenario.

`bytasm serve` refuses self_built mode outside Linux (RLIMIT_AS cannot be
applied there). The e2e suite needs it only to import a *test-generated*
fixture copy with an HTML-like section name (blueprint 9.2 allows this for
test-authored bytes), so it builds the settings directly here. This file is
not part of the installed package and is not a user-facing option.

Usage: python tests/serve_for_e2e.py <data_dir> <port>
"""

import sys
from pathlib import Path

import uvicorn

from bytasm.api.app import create_app
from bytasm.config import Settings

if __name__ == "__main__":
    data_dir, port = Path(sys.argv[1]), int(sys.argv[2])
    settings = Settings(data_dir=data_dir, port=port, input_policy="self_built")
    uvicorn.run(create_app(settings), host="127.0.0.1", port=port, workers=1, log_level="info")
