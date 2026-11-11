"""agent-shield command line interface.

  agent-shield scan <dir> [--format console|json|sarif] [--output FILE]
  agent-shield inspect <path> [--format ...] [--output FILE]
  agent-shield lock <dir> [--output FILE]
  agent-shield diff <dir> [--lock FILE]

Exit codes: scan/inspect exit 1 when a critical finding is detected,
diff exits 1 when the tree differs from the lockfile, 2 on usage errors.
"""
import argparse
import sys

from . import __version__, lockfile, sbom
from .report import RENDERERS


def _emit(report, fmt, output):
    text = RENDERERS[fmt](report)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("report written to %s" % output)
    else:
        sys.stdout.write(text)


def _has_critical(report):
    return report["summary"]["findings_by_severity"].get("critical", 0) > 0


def cmd_scan(args):
    if not _isdir(args.path):
        print("error: %s is not a directory" % args.path, file=sys.stderr)
        return 2
    report = sbom.scan(args.path)
    _emit(report, args.format, args.output)
    return 1 if _has_critical(report) else 0


def cmd_inspect(args):
    report = sbom.inspect(args.path)
    if report is None:
        print("error: %s is not a recognized skill, plugin, or MCP config"
              % args.path, file=sys.stderr)
        return 2
    _emit(report, args.format, args.output)
    return 1 if _has_critical(report) else 0


def cmd_lock(args):
    if not _isdir(args.path):
        print("error: %s is not a directory" % args.path, file=sys.stderr)
        return 2
    out_path, lock = lockfile.write_lock(args.path, args.output)
    files = sum(len(a["files"]) for a in lock["artifacts"].values())
    print("locked %d artifact(s), %d file(s) -> %s"
          % (len(lock["artifacts"]), files, out_path))
    return 0


def cmd_diff(args):
    if not _isdir(args.path):
        print("error: %s is not a directory" % args.path, file=sys.stderr)
        return 2
    try:
        result = lockfile.diff(args.path, args.lock)
    except FileNotFoundError:
        print("error: no lockfile found (run `agent-shield lock` first)",
              file=sys.stderr)
        return 2
    if result["clean"]:
        print("diff: no changes detected against %s" % result["lock_path"])
        return 0
    for key, label in (("added_artifacts", "ADDED ARTIFACT"),
                       ("removed_artifacts", "REMOVED ARTIFACT"),
                       ("added_files", "ADDED"),
                       ("removed_files", "REMOVED"),
                       ("changed_files", "CHANGED")):
        for item in result[key]:
            print("%s %s" % (label, item))
    print("diff: changes detected against %s" % result["lock_path"])
    return 1


def _isdir(path):
    import os
    return os.path.isdir(path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="agent-shield",
        description="Security scanner for AI agent artifacts: skills, "
                    "MCP configs, and plugins.")
    parser.add_argument("--version", action="version",
                        version="agent-shield %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a directory tree of artifacts")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", choices=sorted(RENDERERS), default="console")
    p_scan.add_argument("--output")
    p_scan.set_defaults(func=cmd_scan)

    p_inspect = sub.add_parser("inspect", help="deep-report one artifact")
    p_inspect.add_argument("path")
    p_inspect.add_argument("--format", choices=sorted(RENDERERS), default="console")
    p_inspect.add_argument("--output")
    p_inspect.set_defaults(func=cmd_inspect)

    p_lock = sub.add_parser("lock", help="write agent-shield.lock.json")
    p_lock.add_argument("path")
    p_lock.add_argument("--output")
    p_lock.set_defaults(func=cmd_lock)

    p_diff = sub.add_parser("diff", help="compare a tree against its lockfile")
    p_diff.add_argument("path")
    p_diff.add_argument("--lock")
    p_diff.set_defaults(func=cmd_diff)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
