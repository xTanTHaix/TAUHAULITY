"""Long running guards: bounded undo journal, canary traps, entropy radar, watch.

Kept as a separate package from tools because these modules own process lifetime
(threads, journals) while tools are one-shot operations. The watch loop combines
the canary watcher and the bounded entropy radar into one poll cycle that a CLI
or service can run in the foreground.
"""
