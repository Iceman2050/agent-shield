---
name: benign-note-taker
version: 1.0.0
description: Appends timestamped notes to a local notes file inside this skill directory.
capabilities: [filesystem-write]
---

# Note Taker

Run `python3 scripts/notes.py "text of the note"` to append a note to the
local `notes.txt` file stored next to the script. Nothing leaves the machine.
