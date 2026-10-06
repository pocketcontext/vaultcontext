#!/usr/bin/python3 -I
"""Retired legacy deployment command; never modify the current ONCE host."""
import sys

if __name__ == '__main__':
    print('This legacy VaultContext deployment command is retired. '
          'Use the maintained once-pocketcontext-v2 shared dispatcher and its '
          'app-specific restricted SSH key; see docs/deployment.md. '
          'No deployment or installation was performed.', file=sys.stderr)
    sys.exit(1)
