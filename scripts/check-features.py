#!/usr/bin/env python3
"""Verify crate feature flags and dependency boundaries across the workspace.

Running `cargo check --workspace` unifies features across all workspace members
at once (e.g., `sigstore-sign` enables `sigstore-rekor/client`, hiding whether
`sigstore-verify` or `sigstore-rekor` still compiles without it). This script
checks each crate in isolation (--package <crate>) to verify:
  1. Compilation with default features, no features, and each individual feature.
  2. Non-`rustls` features (such as `native-tls`) do not pull in `rustls`.
  3. Offline crate configurations do not pull in HTTP or async runtime crates.
"""
import json
import subprocess


def normal_dependencies(package: str, *flags: str) -> set[str]:
    """Return the set of normal (non-dev, non-build) dependency crate names."""
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    return {line.split()[0] for line in tree.splitlines() if line.strip()}


metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
))
for package in metadata["packages"]:
    name = package["name"]
    # `--lib` fails on binary-only packages (like `sigstore-conformance`), so
    # only include it when the package actually defines a library target.
    targets = ["--bins", "--examples"]
    if any("lib" in t["kind"] for t in package["targets"]):
        targets.append("--lib")

    # 1. Check that the crate compiles in isolation under:
    #    - default features
    #    - `--no-default-features`
    #    - each non-default feature enabled on its own
    variants = [[], ["--no-default-features"]]
    variants += [
        ["--no-default-features", "--features", feature]
        for feature in package["features"]
        if feature != "default"
    ]
    for flags in variants:
        subprocess.run(
            ["cargo", "check", "--locked", "--package", name, *targets, *flags],
            check=True,
        )

    # 2. Check that enabling all non-`rustls` features together (e.g.
    #    `native-tls`, `tuf`, `client`/`fetch`, `browser`) does not pull the
    #    `rustls` TLS stack into normal dependencies.
    non_rustls = [f for f in package["features"] if f not in ("default", "rustls")]
    flags = ["--no-default-features"]
    if non_rustls:
        flags += ["--features", ",".join(non_rustls)]
    if "rustls" in normal_dependencies(name, *flags):
        raise SystemExit(f"{name} pulls in rustls without its rustls feature")

# 3. Check that offline-capable crates do not pull in HTTP clients or the Tokio
#    runtime when their network features (`tuf`, `client`, `fetch`) are disabled.
for package, flags in [
    ("sigstore-verify", []),
    ("sigstore-verify", ["--no-default-features"]),
    ("sigstore-bundle", []),
    ("sigstore-rekor", ["--no-default-features"]),
    ("sigstore-tsa", ["--no-default-features"]),
    ("sigstore-tuf", ["--no-default-features"]),
    ("sigstore-trust-root", ["--no-default-features"]),
]:
    forbidden = normal_dependencies(package, *flags) & {"reqwest", "hyper", "tokio"}
    if forbidden:
        raise SystemExit(f"{package} unexpectedly requires {sorted(forbidden)}")
