#!/usr/bin/env bash
# US-1613 — verify the RP2350 debug-access posture an image class must be in.
#
# Red-team F2 (HIGH): `picotool info -a` over BOOTSEL reports
#
#     secure boot:            0
#     debug enable:           1
#     secure debug enable:    1
#
# With the debug interface open, brief physical possession is enough to attach
# SWD and dump RAM, where `derive_store_key`'s output, the ECDH `hkey`,
# `device_random` and the per-applet keys are resident. That is complete key
# exfiltration, and it bypasses every other control the assessment found
# holding. This is the *terminal objective* every presence gate in
# US-1601…US-1606 defends against, which is why it is a release gate and not
# a bug: while it is open, those gates are the outer wall of a house with no
# roof.
#
# Per ADR 0002 the closure applies at `-release` tags and the repository
# carries no tags yet, so the current board reading above is *consistent with
# policy* — and "consistent with" is exactly what this script exists to
# replace with "verified".
#
# Usage
# -----
#   check_release_debug_state.sh --self-test
#       Runs the parser and the policy against recorded readings. No hardware,
#       no picotool. This is what CI can run.
#
#   check_release_debug_state.sh --from-text FILE [--class CLASS]
#       Parse a saved `picotool info -a` capture. CLASS is `release` (default)
#       or `pre-release`.
#
#   check_release_debug_state.sh [--class CLASS]
#       Read the attached device. Requires the board in BOOTSEL and picotool.
#
# Exit codes
# ----------
#   0  posture matches the class
#   1  posture does NOT match the class  (the release gate failing)
#   2  usage / environment error (picotool missing, unparseable capture)
#   3  --self-test failed
#
# Deliberately NOT in run_tests.sh: it needs hardware. Wired into the release
# checklist instead, which is where a once-per-tag check belongs.

set -uo pipefail

SELF="$(basename "$0")"

# ---------------------------------------------------------------------------
# The policy, in one table
# ---------------------------------------------------------------------------
#
# ADR 0002, `docs/adr/0002-provisioning-policy.md`:
#
#   image class      debug port            irreversible OTP burns
#   alpha / beta     available             none
#   -release tag     closure applies       as decided at the time
#
# So `pre-release` does not merely *permit* an open debug port — it is the
# documented posture, and a board that failed this class would mean the
# closure fired early and burnt a fuse nobody intended. That asymmetry is why
# this script gates both directions instead of only failing when debug is
# open: a gate that cannot also catch an over-eager burn is half a gate.
#
# **`secure boot` is 1 for a release, not 0.**
#
# The epic's draft wrote "secure boot, debug enable and secure debug enable
# are all 0", and that is wrong on the first field: `0` is the *unset* state,
# so gating on it would demand that a release image ship with signed boot
# DISABLED — the exact opposite of what `build-signed.sh` produces, and of
# what `docs/secureboot.md` exists to enable.
#
# The numbers are fuse/flag states, read off this repository's only hardware
# reading (`redteam/SECURITY_ASSESSMENT.md` F2): that board reports
# `secure boot: 0` and does not verify signatures, and `debug enable: 1` and
# does accept a debugger. So a release wants signed boot ON and both debug
# paths OFF:
#
#     secure boot = 1   CRIT1.SECURE_BOOT_ENABLE set
#     debug enable = 0  CRIT1.DEBUG_DISABLE set — no plain SWD
#     secure debug = 0  CRIT1.SECURE_DEBUG_DISABLE set — no debug under
#                                   signed boot either
EXPECT_RELEASE="1 0 0"         # secure boot, debug enable, secure debug enable
EXPECT_PRERELEASE="any any any" # no constraint; report only

# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

# Pull the three CRIT1-sampled values out of a `picotool info -a` capture.
#
# Picotool prints them as "secure boot:", "debug enable:" and "secure debug
# enable:" with the value last on the line. Matching on the LABEL and taking
# the last field is deliberate: it does not depend on column alignment, which
# has changed between picotool releases, and the third label is a superstring
# of nothing the first two match — "debug enable" would not match "secure
# debug enable" because the match is anchored at the start of the field.
#
# A missing line yields "" and is reported as a PARSE failure rather than
# defaulting to 0. Defaulting a missing "debug enable:" to 0 would report a
# CLOSED port that was never observed, which is the one wrong answer this
# script must never give.
parse_info_a() {
    awk '
        /^[[:space:]]*secure boot:/         { sb = $NF }
        /^[[:space:]]*debug enable:/        { de = $NF }
        /^[[:space:]]*secure debug enable:/ { sde = $NF }
        END { printf "%s %s %s\n", sb, de, sde }
    ' "$1"
}

# Report one capture against one expected triple.
# Prints a verdict line per field; returns 0 iff all three match.
check_capture() {
    local text_file="$1" class="$2"
    local got expect label fails=0

    got="$(parse_info_a "$text_file")"
    if [ -z "${got// /}" ]; then
        # Exit 2, not 1: "we could not observe the posture" is a different
        # statement from "the posture is wrong", and conflating them would let
        # a broken picotool invocation and a genuinely open debug port print
        # the same verdict. Both are non-zero, so the gate still blocks, but
        # the operator is told which one happened.
        echo "$SELF: CANNOT VERIFY — no CRIT1 field readable in $text_file" >&2
        echo "       Expected 'picotool info -a' output with 'secure boot:'," >&2
        echo "       'debug enable:' and 'secure debug enable:' lines. A capture" >&2
        echo "       with none of them is NOT evidence of a closed debug port." >&2
        return 2
    fi

    case "$class" in
        release)     expect="$EXPECT_RELEASE" ;;
        pre-release) expect="$EXPECT_PRERELEASE" ;;
        *)
            echo "$SELF: unknown --class '$class' (release | pre-release)" >&2
            return 2
            ;;
    esac

    echo "$SELF: class=$class  observed: secure boot / debug enable / secure debug enable"
    echo "       got      = $got"

    local i=0
    for label in "secure boot" "debug enable" "secure debug enable"; do
        local v
        v="$(echo "$got" | cut -d' ' -f$((i + 1)))"
        if [ -z "$v" ]; then
            echo "       $label = <absent from capture>  FAIL (unobserved, not '0')"
            fails=$((fails + 1))
        elif [ "$expect" = "$EXPECT_PRERELEASE" ]; then
            echo "       $label = $v   (no constraint for this class)"
        else
            local want
            want="$(echo "$expect" | cut -d' ' -f$((i + 1)))"
            if [ "$v" = "$want" ]; then
                echo "       $label = $v   OK"
            else
                echo "       $label = $v   FAIL (want $want)"
                fails=$((fails + 1))
            fi
        fi
        i=$((i + 1))
    done

    if [ "$fails" -ne 0 ]; then
        if [ "$class" = release ]; then
            echo "$SELF: FAIL $fails/3 CRIT1 field(s) wrong for a -release image."
            echo "       CRIT1.DEBUG_DISABLE / SECURE_DEBUG_DISABLE are OTP fuses sampled by the"
            echo "       bootrom at reset: no build flag reaches them and CI cannot burn them."
            echo "       Do not ship this tag. See docs/adr/0002-provisioning-policy.md."
        else
            echo "$SELF: FAIL $fails/3 CRIT1 field(s) unreadable for a pre-release image."
        fi
        return 1
    fi

    if [ "$class" = release ]; then
        echo "$SELF: OK — debug port closed, secure boot on. The F2 closure fired."
    else
        echo "$SELF: OK — pre-release posture. Debug access is OPEN by ADR 0002 policy;"
        echo "       see docs/SECURITY-ASSESSMENT-ROUND2.md and the threat-model note."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

# The recorded pre-release reading, verbatim from
# redteam/SECURITY_ASSESSMENT.md F2 (2026-10-05, live board over BOOTSEL).
# This is the only hardware reading in the repository and it is the fixture
# the whole story is about.
read -r -d '' CAPTURE_PRERELEASE <<'EOF' || true
Program Information
 name:          rp2350
 features:      USB stdin stdout
 flash size:    0x400000
 workspace size:0x80000
 secure boot:            0
 debug enable:           1
 secure debug enable:    1
EOF

# A POST-closure reading. **Synthesised, not measured** — no board in this
# repository has had the fuses burned, because ADR 0002 defers it to the first
# -release tag. It exists so the parser and the policy are exercised in both
# directions without hardware; the hardware proof is the story's acceptance
# criterion and must be recorded from a real board before the first tag. This
# line is the reason the script says so out loud rather than letting the
# fixture look like evidence.
read -r -d '' CAPTURE_RELEASE <<'EOF' || true
Program Information
 name:          rp2350
 features:      USB stdin stdout
 flash size:    0x400000
 workspace size:0x80000
 secure boot:            1
 debug enable:           0
 secure debug enable:    0
EOF

# A capture with the debug lines absent entirely — the parser must report this
# as UNREADABLE, never as "0", or a broken picotool invocation would be
# indistinguishable from a closed debug port.
read -r -d '' CAPTURE_ABSENT <<'EOF' || true
Program Information
 name:          rp2350
 flash size:    0x400000
EOF

self_test() {
    local d rc=0
    d="$(mktemp -d)"
    trap 'rm -rf "$d"' RETURN

    printf '%s\n' "$CAPTURE_PRERELEASE" > "$d/pre.txt"
    printf '%s\n' "$CAPTURE_RELEASE"    > "$d/rel.txt"
    printf '%s\n' "$CAPTURE_ABSENT"     > "$d/absent.txt"

    echo "== 1. the recorded pre-release board, checked as RELEASE — must FAIL"
    check_capture "$d/pre.txt" release
    local got=$?
    [ "$got" -eq 1 ] || { echo "$SELF: self-test FAIL — expected exit 1, got $got"; rc=1; }
    echo

    echo "== 2. the same reading, checked as PRE-RELEASE — must PASS (ADR 0002 posture)"
    check_capture "$d/pre.txt" pre-release
    got=$?
    [ "$got" -eq 0 ] || { echo "$SELF: self-test FAIL — expected exit 0, got $got"; rc=1; }
    echo

    echo "== 3. a post-closure reading, checked as RELEASE — must PASS"
    check_capture "$d/rel.txt" release
    got=$?
    [ "$got" -eq 0 ] || { echo "$SELF: self-test FAIL — expected exit 0, got $got"; rc=1; }
    echo

    echo "== 4. a capture with no CRIT1 lines — must be CANNOT VERIFY (exit 2), never pass"
    check_capture "$d/absent.txt" release
    got=$?
    [ "$got" -eq 2 ] || { echo "$SELF: self-test FAIL — expected exit 2, got $got"; rc=1; }
    echo

    echo "== 5. an unknown class is a usage error"
    check_capture "$d/pre.txt" wat
    got=$?
    [ "$got" -eq 2 ] || { echo "$SELF: self-test FAIL — expected exit 2, got $got"; rc=1; }

    [ "$rc" -eq 0 ] && echo "$SELF: self-test OK"
    return $rc
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CLASS=release
TEXT=""
DO_SELF=0

while [ $# -gt 0 ]; do
    case "$1" in
        --self-test) DO_SELF=1 ;;
        --class)     shift; CLASS="${1:-}" ;;
        --from-text) shift; TEXT="${1:-}" ;;
        -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "$SELF: unknown argument '$1' (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ "$DO_SELF" -eq 1 ]; then
    self_test
    exit $?
fi

if [ -n "$TEXT" ]; then
    [ -r "$TEXT" ] || { echo "$SELF: cannot read $TEXT" >&2; exit 2; }
    check_capture "$TEXT" "$CLASS"
    exit $?
fi

command -v picotool >/dev/null 2>&1 || {
    echo "$SELF: picotool not found. Put the board in BOOTSEL and install picotool," >&2
    echo "       or re-run with --from-text on a saved 'picotool info -a' capture." >&2
    exit 2
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
picotool info -a > "$TMP" 2>&1 || {
    echo "$SELF: 'picotool info -a' failed — is the board in BOOTSEL?" >&2
    sed -n '1,20p' "$TMP" >&2
    exit 2
}
check_capture "$TMP" "$CLASS"
exit $?