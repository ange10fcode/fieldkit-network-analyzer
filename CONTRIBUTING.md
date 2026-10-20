# Contributing

Use focused changes with a description of the concrete problem and resulting
behavior. Include relevant tests and platform details. Never add demonstration
device inventories, inferred radio distances, silent routing changes or fake
successful probes to production screens.

Before opening a pull request:

1. Read `docs/BUILDING.md` and run the checks for the platform you changed.
2. Keep shared version metadata consistent with `VERSION`.
3. Preserve observation timestamps and clearly label unavailable capabilities.
4. Add meaningful parser/network/persistence regressions for relevant changes.
5. Run `python scripts/verify_release.py` before committing.

Do not commit local reports, personal network addresses, build caches, passwords,
keystores, certificates or provisioning profiles. Third-party dependencies must
be pinned and their required notices retained. Contributions are under the
repository's MIT license; third-party code retains its own license.
