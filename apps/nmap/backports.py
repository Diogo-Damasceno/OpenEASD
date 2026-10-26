import json
import re
from pathlib import Path

BACKPORTS_FILE = Path(__file__).parent / "backports.json"

def _load_backports():
    if not BACKPORTS_FILE.exists():
        return {}
    with open(BACKPORTS_FILE, "r") as f:
        return json.load(f)

BACKPORTS = _load_backports()

def compare_debian_versions(v1: str, v2: str) -> int:
    """
    Simplified Debian version compare.
    Returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2.
    """
    def parse_parts(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'([0-9]+)', v) if x]

    p1 = parse_parts(v1)
    p2 = parse_parts(v2)

    for a, b in zip(p1, p2):
        if a == b:
            continue
        if type(a) is type(b):
            return 1 if a > b else -1
        # In debian, strings and numbers compare strangely, but casting to str works for most simple cases
        return 1 if str(a) > str(b) else -1

    if len(p1) > len(p2):
        return 1
    elif len(p1) < len(p2):
        return -1
    return 0

def _rpm_segment_compare(left: str, right: str) -> int:
    """Compare a VERSION or RELEASE component using rpmvercmp ordering."""
    i = j = 0

    def is_digit(char: str) -> bool:
        return "0" <= char <= "9"

    def is_alpha(char: str) -> bool:
        return "a" <= char <= "z" or "A" <= char <= "Z"

    def is_alnum(char: str) -> bool:
        return is_digit(char) or is_alpha(char)

    while i < len(left) or j < len(right):
        while i < len(left) and not (is_alnum(left[i]) or left[i] in "~^"):
            i += 1
        while j < len(right) and not (is_alnum(right[j]) or right[j] in "~^"):
            j += 1

        first = left[i] if i < len(left) else ""
        second = right[j] if j < len(right) else ""

        # Tilde sorts below everything, including a missing segment.
        if first == "~" or second == "~":
            if first != "~":
                return 1
            if second != "~":
                return -1
            i += 1
            j += 1
            continue

        # Caret sorts after the bare version, but before the next segment.
        if first == "^" or second == "^":
            if not first:
                return -1
            if not second:
                return 1
            if first != "^":
                return 1
            if second != "^":
                return -1
            i += 1
            j += 1
            continue

        if not first or not second:
            break

        numeric = is_digit(first)
        start_i, start_j = i, j
        if numeric:
            while i < len(left) and is_digit(left[i]):
                i += 1
            while j < len(right) and is_digit(right[j]):
                j += 1
        else:
            while i < len(left) and is_alpha(left[i]):
                i += 1
            while j < len(right) and is_alpha(right[j]):
                j += 1

        one, two = left[start_i:i], right[start_j:j]
        if not two:
            # Numeric segments always sort after alphabetic segments.
            return 1 if numeric else -1

        if numeric:
            one, two = one.lstrip("0") or "0", two.lstrip("0") or "0"
            if len(one) != len(two):
                return 1 if len(one) > len(two) else -1
        if one != two:
            return 1 if one > two else -1

    return (i < len(left)) - (j < len(right))


def compare_rpm_versions(v1: str, v2: str) -> int:
    """Compare RPM epoch:version-release values, with missing epoch = 0.

    Compare epoch first, then version and release separately using RPM rules.
    Unlike stripping epochs, this cannot mark an older epoch as patched.
    """

    def split_evr(value: str):
        epoch = 0
        prefix, sep, suffix = value.partition(":")
        if sep and prefix.isascii() and prefix.isdecimal():
            epoch = int(prefix)
            value = suffix
        version, sep, release = value.partition("-")
        return epoch, version, release if sep else ""

    epoch1, version1, release1 = split_evr(v1)
    epoch2, version2, release2 = split_evr(v2)
    if epoch1 != epoch2:
        return 1 if epoch1 > epoch2 else -1

    result = _rpm_segment_compare(version1, version2)
    if result:
        return result
    return _rpm_segment_compare(release1, release2)


# Distro marker -> canonical backports.json key -> version family.
# Alpine is tracked separately in #575 because its nmap banner format
# needs independent verification. Adding a source here does not assume
# an unverified Alpine suffix format.
_DISTRO_RULES = (
    (re.compile(r"(?i)\bubuntu\b"), "ubuntu", "deb"),
    (re.compile(r"(?i)\bdebian\b"), "debian", "deb"),
    (re.compile(r"(?i)\b(?:sles|opensuse|suse)\b"), "suse", "rpm"),
    (
        re.compile(
            r"(?i)\b(?:rhel|red\s+hat|rocky(?:\s+linux)?|alma(?:linux)?|centos|oracle\s+linux)\b"
        ),
        "redhat",
        "rpm",
    ),
)

# Require a recognizable distro package-build suffix. A version mentioned in
# generic service metadata (e.g. "Ubuntu Linux; protocol 2.0") must not cause
# a false security demotion.
_DEB_VERSION_RE = r"[-;]\s*(\d[a-z0-9.~+-]*)"
_RPM_VERSION_RE = (
    r"(?:[\s;:-]+)((?:[0-9]+:)?[0-9][0-9A-Za-z._~+]*-[0-9A-Za-z._~+]+)"
    r"(?![0-9A-Za-z._~+])"
)


def check_backport(product: str, version_string: str, cve: str) -> dict:
    """Only demote a CVE when the installed distro build meets the fixed build."""
    if not product or not version_string:
        return None

    product = product.lower()
    for marker, distro, family in _DISTRO_RULES:
        match = marker.search(version_string)
        if match is None:
            continue
        expression = _RPM_VERSION_RE if family == "rpm" else _DEB_VERSION_RE
        build = re.search(expression, version_string[match.end():])
        if build is None:
            continue

        fixed = BACKPORTS.get(distro, {}).get(cve, {}).get(product)
        if not fixed:
            continue

        comparator = compare_rpm_versions if family == "rpm" else compare_debian_versions
        if comparator(build.group(1), fixed) >= 0:
            return {"backport_applied": True, "first_fixed_in": fixed}

    return None
