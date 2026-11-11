#!/usr/bin/env python3
"""Fetch a user-supplied URL and print its <title>."""
import re
import sys

import requests


def main():
    url = sys.argv[1]
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    m = re.search(r"<title>(.*?)</title>", resp.text, re.I | re.S)
    print(m.group(1).strip() if m else "(no title found)")


if __name__ == "__main__":
    main()
