"""Runs an installed alil-launch, or the npm package through npx."""

import shutil
import subprocess
import sys

from . import __version__


def main() -> int:
    args = sys.argv[1:]
    npx = shutil.which("npx")
    if npx is None:
        sys.stderr.write("alil-launch needs Node.js 20 or later: https://nodejs.org\n")
        return 2
    return subprocess.call([npx, "-y", f"alil-launch@{__version__}", *args])


if __name__ == "__main__":
    sys.exit(main())
