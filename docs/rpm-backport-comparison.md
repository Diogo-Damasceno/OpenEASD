# RPM-aware Nmap backport comparisons

Related issue: [#576](https://github.com/cybersecify/OpenEASD/issues/576). Origin: [SUSE PR #433](https://github.com/cybersecify/OpenEASD/pull/433) and [Red Hat PR #432](https://github.com/cybersecify/OpenEASD/pull/432).

## Why

The existing Debian-oriented comparator cannot reliably order RPM builds. Incorrect ordering can produce a false security verdict. `check_backport()` must only demote a vulnerability finding when an installed package build compares greater than or equal to the known fixed version.

## Version ordering

RPM builds use `EPOCH:VERSION-RELEASE`. The comparison performs these steps, in order:

1. Compare numeric epochs; an omitted epoch is zero.
2. Compare the VERSION fields using RPM segment rules.
3. If versions are equal, compare the RELEASE fields using those same rules.

For each component, numeric runs compare as numbers (ignoring leading zeros), numeric segments sort after alphabetic segments, `~` marks a version older than a corresponding plain version, and `^` marks a post-release newer than the plain version but older than a following ordinary segment. Punctuation otherwise separates segments.

For example, `2:1.0-1` sorts after `1:9.9-9`; `1.0~rc1` sorts before `1.0`; `1.0^git1` sorts after `1.0` but before `1.0.1`.

**Epoch caveat:** package metadata and service banners may not carry matching epoch information. It is not safe to ignore a known nonzero epoch. When a banner lacks sufficient fixed-build detail, do not demote the finding.

## Distro selection

`_DISTRO_RULES` maps recognized SUSE/openSUSE/SLES and Red Hat family markers to the RPM comparator, while Ubuntu and Debian retain the existing Debian comparator. RPM detection requires a build with a release suffix, rather than matching a distribution version alone. The Alpine consumer remains out of scope under [#575](https://github.com/cybersecify/OpenEASD/issues/575).

Version strings supplied by Nmap vary; regression fixtures check representative shapes, not an exhaustive inventory of real-world `-sV` output. An unrecognized banner fails closed: it returns no backport demotion.

## Verification

Focused project tests:

```sh
uv run pytest tests/unit/test_nmap_backports.py -q
uv run ruff check apps/nmap/backports.py tests/unit/test_nmap_backports.py
```

A standalone local extraction of the comparator and marker-matching behavior passed 33 parameterized cases before repository publication. Full project CI and integration testing must still run on the GitHub pull request; **do not interpret the standalone check as CI green**.

No new runtime dependency is required.

## Follow-up

The original #433 and #432 branches still include their older shared comparator. Once this independently reviewed change lands, those branches can be adjusted to reuse the common implementation and avoid duplicate logic.
