#!/usr/bin/env python3
"""Check each workspace crate without workspace-wide feature unification."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
))
for package in metadata["packages"]:
    variants = [[], ["--no-default-features"]]
    variants += [
        ["--no-default-features", "--features", feature]
        for feature in package["features"]
        if feature != "default"
    ]
    for flags in variants:
        subprocess.run(
            ["cargo", "check", "--locked", "--package", package["name"], *flags],
            check=True,
        )

# Offline consumers must not regain a hidden HTTP/runtime dependency.
for package, flags in [
    ("sigstore-verify", []),
    ("sigstore-verify", ["--no-default-features"]),
    ("sigstore-bundle", []),
    ("sigstore-rekor", ["--no-default-features"]),
    ("sigstore-tsa", ["--no-default-features"]),
]:
    tree = subprocess.check_output(
        ["cargo", "tree", "--locked", "--package", package,
         "--edges", "normal", "--prefix", "none", *flags], text=True,
    )
    dependencies = {line.split()[0] for line in tree.splitlines() if line.strip()}
    forbidden = dependencies & {"reqwest", "hyper", "tokio"}
    if forbidden:
        raise SystemExit(f"{package} unexpectedly requires {sorted(forbidden)}")
