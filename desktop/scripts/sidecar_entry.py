"""Entry point of the frozen sidecar: the command line of boxed, unchanged. The shell starts it as `boxed serve`."""

import sys

from boxed.cli import main

if __name__ == "__main__":
    sys.exit(main())
