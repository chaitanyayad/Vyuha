import sys
from pathlib import Path

# The suites import gateway/, agent/, sandbox/ and redteam/ as top-level
# packages, so the repo root has to be importable regardless of where pytest
# was invoked from.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
