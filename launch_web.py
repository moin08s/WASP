"""Launcher for WASP Tactical DFIR Web Application Console."""

import sys
import webbrowser
from pathlib import Path

def main():
    web_file = Path(__file__).parent / "web" / "index.html"
    if not web_file.exists():
        print(f"[-] Error: Web console not found at {web_file}")
        sys.exit(1)
        
    print("===========================================================================")
    print("  LAUNCHING WASP TACTICAL DFIR WEB APPLICATION CONSOLE")
    print("===========================================================================")
    print(f"  URL: {web_file.as_uri()}")
    print("  Theme: Tactical Dark Mode | High-Density Card Layout | Wasp Accent")
    print("===========================================================================")
    webbrowser.open(web_file.as_uri())

if __name__ == "__main__":
    main()
