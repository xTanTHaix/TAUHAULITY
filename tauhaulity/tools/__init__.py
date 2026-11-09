"""Developer facing tools: git sentinel, hook gate, port sweeper, venv radar.

The allowlist module records accepted credential fingerprints for the sentinel and
the shim module installs the undo-aware delete wrapper for bash and PowerShell.

Submodules are imported explicitly by their callers instead of being re-exported
here, so importing one tool never drags in the others (the port sweeper probes
the Windows IP helper API, which has no business running inside a git hook).
"""
