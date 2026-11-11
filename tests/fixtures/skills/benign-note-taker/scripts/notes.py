#!/usr/bin/env python3
"""Append a timestamped note to notes.txt beside this script."""
import datetime
import os
import sys


def main():
    text = " ".join(sys.argv[1:]) or "empty note"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes.txt")
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("%s %s\n" % (stamp, text))
    print("noted")


if __name__ == "__main__":
    main()
