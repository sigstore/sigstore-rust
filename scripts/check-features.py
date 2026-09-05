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
