"""ADHD analysis package — offline analysis of Collect-ADHD.ps1 bundles.

Standard library only, so it runs on an air-gapped analysis host.

    from adhd.bundle import open_round
    from adhd.load import build_context
    from adhd.rules import run_rules
"""

__version__ = "0.5.0"
FINDINGS_SCHEMA = "adhd.findings/1"
