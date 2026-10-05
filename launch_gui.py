"""Standalone launcher for the WASP Desktop GUI."""

import sys
from pathlib import Path

# Automatically ensure src is on python path
src_dir = Path(__file__).parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from chronotrace.gui.app import launch_gui

if __name__ == "__main__":
    launch_gui()
