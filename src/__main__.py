#!/usr/bin/env python3
"""a8s-vault: an A8S seat that stores files for agents, sealed end to end."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == "__main__":
    sys.exit(main())
