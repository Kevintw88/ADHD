"""Import shim so tests can call tools/detect.py's main() (tools/ is not a package)."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location("adhd_tools_detect", Path(__file__).resolve().parents[2] / "tools" / "detect.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
main = _mod.main
