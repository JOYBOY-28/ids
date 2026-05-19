import runpy

from live_pipline import *  # Backward-compatible wrapper for the misspelled module.


if __name__ == "__main__":
    runpy.run_module("live_pipline", run_name="__main__")
