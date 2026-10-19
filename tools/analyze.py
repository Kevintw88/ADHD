#!/usr/bin/env python3
"""Analyse one ADHD collection round. See adhd/analyze.py.

    python3 tools/analyze.py ADHD-Collect-SubA*20261015*.zip --out /srv/adhd/reports/SubA-20261015
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adhd.analyze import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
