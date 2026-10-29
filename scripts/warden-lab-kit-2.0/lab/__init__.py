"""Warden Lab Kit 2.0 — a declarative lab and production reference for Warden.

The package has no third-party dependencies; it targets the Python that ships
with Ubuntu 24.04 (3.12). ``labctl`` is the single entry point; everything
else here is a library it drives.
"""

VERSION = "2.0.1"
# The Warden release line this kit targets. The daemon version is pinned in
# the profile (``[warden] version`` / ``sha256``), never here.
TARGETS_WARDEN = "0.14.3"
