#!/usr/bin/env python3
"""Pre-deploy gate for the additive-asset genesis door (soqucoin PR #83).

Scans a live stagenet chain for the rules that the v2.4.0 tag TIGHTENS on an
existing chain, so that a fleet node carrying the new binary is proven to
accept every block already in stagenet history before it is deployed. Four
detectors, T1, T2, T2b and T3:

  T1  a witness-v6 (OP_6 <32>) spend whose witnessScript contains one of
      OP_USDSOQ_MINT/BURN/FREEZE/ROTATE (0xf4-0xf7), OP_SOQUOBSCURA_RANGEPROOF
      (0xfa), OP_CHECKFOLDPROOF (0xfc) or OP_CHECKPATAGG (0xfd), or whose
      witnessScript fails to parse. Mirrors the GetOp scan in
      src/script/interpreter.cpp (P2WSH-Dilithium branch), which rejects with
      SCRIPT_ERR_BAD_OPCODE in every asset-flag state.
  T2  a COINBASE output paying to OP_10 <32> (confidential USDSOQ), now
      rejected by CheckTransaction (IsAnyUSDSOQ) as bad-cb-usdsoq-asset.
  T2b a COINBASE output paying to OP_5 <32> (USDSOQ authority marker), now
      rejected by the same CheckTransaction branch as bad-cb-usdsoq-asset.
      ⚠️ T2 AND T2b CANNOT FIRE ON THIS NETWORK AND THEIR ZEROS CARRY NO
      INFORMATION. ContextualCheckBlock (src/validation.cpp, the
      bad-cb-output-type rule added in 38c4f700e, 2025-11-21) already rejects
      ANY coinbase output that is not OP_1 <32> or OP_RETURN, on every network
      except regtest, at every height above 0. That predates every block of the
      current stagenet chain, so no coinbase asset output has ever been valid
      here. Both detectors are kept as belt-and-braces against a future change
      to that rule; do not cite their zeros as evidence for the CheckTransaction
      bans. The bans themselves are defence in depth, and on regtest they are
      the only such rule.
  T3  a SIGHASH_ANYPREVOUT (0x41) or ANYPREVOUTANYSCRIPT (0x42) signature on the
      single-key Dilithium path. Bead mpu9 made that
      rejection UNCONDITIONAL, and stagenet runs DEPLOYMENT_APO active from
      height 0, so unlike mainnet this network COULD have accepted such a spend.
      Any hit is a block the new binary rejects. Scoped to the single-key
      path by t3_classify: a witness-v6 spend also has a two-item stack,
      [witnessScript, pubkey], and reading the last byte of a witnessScript
      as a hashtype is a false positive.

Everything else the door changes is a loosening or is flag-neutral on stagenet
(USDSOQ and BTCSOQ are active from height 0 there, SoquObscura is dormant), so
those rules cannot reject existing blocks. See the bead
stagenet-scan-before-genesis-door-deploy-nydh and
doc/specifications/WITNESS_VERSION_FORK_CLASS.md.

The instrument proves itself: --selftest exercises the detector on synthetic
inputs (positive and negative), and the live run reports every decode failure
as a count, never as a silent skip. A zero with an unproven instrument is not a
result (the 2026-08-31 v2 scan produced a false zero exactly that way).

Runs ON a stagenet node with RPC credentials in its soqucoin.conf. Read-only:
it issues only getblockhash / getblock / getblockchaininfo.

  python3 stagenet-scan-genesis-door.py --selftest
  nohup python3 stagenet-scan-genesis-door.py --out /root/scan-genesis-door.json &
  python3 stagenet-scan-genesis-door.py --from 73774 --to 76000   # incremental tail
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import sys
import time

BANNED = {0xF4: "OP_USDSOQ_MINT", 0xF5: "OP_USDSOQ_BURN", 0xF6: "OP_USDSOQ_FREEZE",
          0xF7: "OP_USDSOQ_ROTATE", 0xFA: "OP_SOQUOBSCURA_RANGEPROOF",
          0xFC: "OP_CHECKFOLDPROOF", 0xFD: "OP_CHECKPATAGG"}
OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E


def witness_version(spk_hex):
    """Return (version, program_bytes) if scriptPubKey is a witness program
    (CScript::IsWitnessProgram): 4..42 bytes, OP_0 or OP_1..OP_16, then one
    direct push of 2..40 bytes that fills the rest of the script."""
    b = bytes.fromhex(spk_hex)
    if len(b) < 4 or len(b) > 42:
        return None
    if b[0] == 0x00:
        ver = 0
    elif 0x51 <= b[0] <= 0x60:
        ver = b[0] - 0x50
    else:
        return None
    if b[1] < 2 or b[1] > 40 or b[1] != len(b) - 2:
        return None
    return ver, b[2:]


def scan_script(script):
    """GetOp walk. Returns (status, detail): ('ok', None) | ('banned', name) |
    ('parse_fail', offset). Bytes inside pushes are never read as opcodes."""
    pc, n = 0, len(script)
    while pc < n:
        op = script[pc]
        pc += 1
        if op <= OP_PUSHDATA4:
            if op < OP_PUSHDATA1:
                size = op
            elif op == OP_PUSHDATA1:
                if pc + 1 > n:
                    return "parse_fail", pc
                size = script[pc]
                pc += 1
            elif op == OP_PUSHDATA2:
                if pc + 2 > n:
                    return "parse_fail", pc
                size = int.from_bytes(script[pc:pc + 2], "little")
                pc += 2
            else:
                if pc + 4 > n:
                    return "parse_fail", pc
                size = int.from_bytes(script[pc:pc + 4], "little")
                pc += 4
            if pc + size > n:
                return "parse_fail", pc
            pc += size
            continue
        if op in BANNED:
            return "banned", BANNED[op]
    return "ok", None


DILITHIUM_SIG_BYTES = 2420          # src/key.h:23 SIGNATURE_SIZE
DILITHIUM_PUBKEY_BYTES = (1312, 1313)   # raw (CPubKey::GetLen accepts only
                                        # 1312) and the 0x00-prefixed form
                                        # VerifyScript accepts


def t3_classify(stack_hex, tracked_ver):
    """Is this input a single-key-path spend, and if so its base sighash type?

    Approximates the REACHABILITY condition in VerifyScript, rather than
    matching any two witness items. Consensus reaches the IsAPOSigHashType
    rejection (src/script/interpreter.cpp, the single-key Dilithium path in
    VerifyScript) only for v0/v1 and the v7/v8 holding shapes, and only after
    SHA256(pubkey) matches the 32-byte program.

    This function does NOT recompute that hash: progs holds no v0/v1 entries,
    so the program is not available here. It substitutes the prevout version
    and the ML-DSA-44 size check below. Any spend already in a block matched
    the hash by construction, so for the historical question this scan asks,
    the substitution loses nothing.

    A witness-v6 spend ALSO presents a two-item stack, [witnessScript,
    pubkey] (see classify_v6), so treating the last byte of a witnessScript
    as a hashtype is a false positive. Once T3 gates the verdict that would
    be a false FAIL, i.e. a blocked deploy on no evidence.

    tracked_ver is the prevout's witness version when the scan has seen the
    output that created it, else None. progs holds v2+ only, so on a scan
    from height 0 an untracked prevout is v0/v1 -- the shape stagenet uses.
    On an incremental scan (--from > 0) prevouts created below the range are
    also untracked; the shape test below carries the discrimination there,
    and the residual error direction is a false FAIL, never a false PASS.

    Returns (status, base_sighash_type|None); status is one of "checked",
    "not_single_key", "not_dilithium_shape", "undecodable".
    """
    if len(stack_hex) != 2 or not stack_hex[0]:
        return "not_single_key", None
    if tracked_ver is not None and tracked_ver not in (7, 8):
        return "not_single_key", None
    try:
        sig = bytes.fromhex(stack_hex[0])
        pubkey = bytes.fromhex(stack_hex[1])
    except ValueError:
        return "undecodable", None
    if not sig:
        return "undecodable", None
    # A spend that reached a block under the OLD binary passed CheckSig, so
    # its signature and pubkey are real ML-DSA-44 objects of known size.
    # Any other two-item shape cannot be a block this binary newly rejects.
    if len(sig) != DILITHIUM_SIG_BYTES + 1 or len(pubkey) not in DILITHIUM_PUBKEY_BYTES:
        return "not_dilithium_shape", None
    return "checked", sig[-1] & 0x7F


# Every tightening this scan detects. main() builds its hit lists FROM this
# tuple and compute_verdict REQUIRES exactly these keys, so a detector cannot
# be dropped from the VERDICT side without an immediate, loud failure.
#
# ⛔ THE WIRING HAS TWO SIDES AND THIS TUPLE ONLY GUARDS ONE. Bead mpu9's T3 was
# collected, printed and serialised, and then left out of the verdict, so a real
# hit reported PASS. The first fix tested compute_verdict in isolation, which
# did not help: the function is generic over its keys, so the assertions held
# for any key set and the mutation that mattered was at the CALL SITE. The
# second fix introduced this tuple, which closes the verdict side. Review then
# broke the COLLECTION side instead -- change `if ver == 5` to `if ver == 55`,
# or the T3 hashtype test to a value that never matches -- and the detector
# silently collected nothing while every control still read green.
#
# So the collection side is guarded two ways.
#
#   1. The match conditions are no longer inline glue in main(). They are
#      COINBASE_BANNED_VERSIONS and is_apo_base(), which --selftest drives
#      directly. The specific mutations review used are now either impossible
#      or caught before the scan starts.
#   2. collection_controls() compares each hit list against a counter
#      incremented on a DIFFERENT line from a DIFFERENT expression in the same
#      loop, so a detector that stops appending disagrees with its own counter.
#      ⚠️ This second guard can only fire on a chain that CONTAINS a positive:
#      on a clean chain 0 == 0 either way. It catches a real hit being dropped,
#      which is the failure that matters, but it does not prove a detector
#      works. That proof is (1)'s job.
SCAN_TESTS = ("T1", "T2", "T2b", "T3")

# Which coinbase output version belongs to which detector. A TABLE, not a chain
# of `if ver == N` in main(), because glue in main() is not reachable from
# --selftest: review mutated `ver == 5` to `ver == 55` and every check stayed
# green. coinbase_detector() is driven directly by selftest below.
COINBASE_BANNED_VERSIONS = {10: "T2", 5: "T2b"}

# The sighash base types the single-key path now rejects unconditionally.
APO_BASE_TYPES = (0x41, 0x42)     # ANYPREVOUT, ANYPREVOUTANYSCRIPT


def coinbase_detector(ver):
    """Detector name for a coinbase output witness version, or None."""
    return COINBASE_BANNED_VERSIONS.get(ver)


def is_apo_base(base):
    """Is this base sighash type one the single-key path now rejects?"""
    return base in APO_BASE_TYPES


def collection_controls(hits, v6, cb_outputs, t3):
    """Cross-checks tying each hit list to a separately maintained count.

    SCAN_TESTS guards the verdict side of the wiring. These guard the
    collection side: every counter is incremented on a different line from the
    condition that appends, so REMOVING AN APPEND makes the pair disagree.

    ⛔ THREE OF THE FOUR ALSO CATCH A BROKEN MATCH CONDITION. T1 DOES NOT.
    T2, T2b and T3 count something computed BEFORE their match runs -- the
    output's witness version, and the decoded hashtype -- so breaking
    COINBASE_BANNED_VERSIONS or APO_BASE_TYPES moves the hit list and leaves
    the counter behind. T1's counter is v6[status], and `status` IS the
    classification its append condition reads, so dropping an entry from BANNED
    makes the spend classify "ok" and BOTH sides fall to zero, on a chain that
    CONTAINS the hit. Measured: deleting OP_USDSOQ_BURN, OP_USDSOQ_ROTATE or
    OP_CHECKFOLDPROOF from BANNED left every control here true and the verdict
    PASS on a v6 spend carrying that opcode.

    An earlier version of this docstring said breaking a match condition made
    the pair disagree, without qualification. It is three of four, and T1 is
    the exception, so T1's match condition rests on guard 1 alone. That is why
    selftest pins BANNED's contents against a literal AND drives every entry
    through scan_script.
    """
    return {
        # v6[status] is incremented for every classified v6 spend; T1 collects
        # the two statuses that are tightenings.
        "t1_hits_match_v6_status_counts":
            len(hits["T1"]) == v6["banned"] + v6["parse_fail"],
        # cb_outputs counts every coinbase output by version, before the
        # version is tested against 10 or 5.
        "t2_hits_match_coinbase_v10_count":
            len(hits["T2"]) == cb_outputs.get(10, 0),
        "t2b_hits_match_coinbase_v5_count":
            len(hits["T2b"]) == cb_outputs.get(5, 0),
        # base_types histograms every decoded hashtype, before the APO test.
        "t3_hits_match_sighash_histogram":
            len(hits["T3"]) == (t3["base_types"].get("0x41", 0)
                                + t3["base_types"].get("0x42", 0)),
    }


def compute_verdict(hits, controls, allow_partial=False):
    """(verdict, exit code) from the hit lists and the positive controls.

    hits maps a test name to its hit list and MUST carry exactly SCAN_TESTS.
    Every entry blocks the deploy: a tightening this binary adds, found in
    history, means a node carrying it would reject a block the chain already
    has.

    allow_partial waives ONLY full_range_scanned, and says so in the verdict
    string. The control itself stays false in the JSON, so the artifact never
    claims a property the run did not have.
    """
    missing = sorted(set(SCAN_TESTS) - set(hits))
    unexpected = sorted(set(hits) - set(SCAN_TESTS))
    if missing or unexpected:
        raise ValueError(
            f"verdict wiring broken: missing {missing}, unexpected {unexpected}. "
            f"compute_verdict must receive exactly SCAN_TESTS ({list(SCAN_TESTS)}); "
            f"a detector that is not passed here cannot block a deploy.")
    fired = sorted(name for name, hs in hits.items() if hs)
    if fired:
        return (f"FAIL - tightening hit in history ({', '.join(fired)}); "
                f"do not deploy, re-decide"), 2
    required = {k: v for k, v in controls.items() if isinstance(v, bool)}
    if allow_partial:
        required.pop("full_range_scanned", None)
    unmet = sorted(k for k, v in required.items() if not v)
    if unmet:
        return (f"FAIL - instrument not proven ({', '.join(unmet)}); "
                f"zero hits mean nothing"), 3
    if allow_partial and not controls.get("full_range_scanned", True):
        return ("PASS over a PARTIAL RANGE - --partial was used, so this does "
                "NOT clear the chain and is not a deploy gate"), 0
    return "PASS", 0


def selftest():
    fails = []
    count = [0]

    def check(name, got, want):
        count[0] += 1
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")

    h32 = "11" * 32
    check("v10 program", witness_version("5a20" + h32)[0], 10)
    check("v6 program", witness_version("5620" + h32)[0], 6)
    check("v0 p2wpkh", witness_version("0014" + "22" * 20)[0], 0)
    check("v1 program", witness_version("5120" + h32)[0], 1)
    check("v2 program", witness_version("5220" + h32)[0], 2)
    check("p2pkh is not a program", witness_version("76a914" + "22" * 20 + "88ac"), None)
    check("bad push len", witness_version("5a21" + h32), None)
    check("OP_16", witness_version("6020" + h32)[0], 16)
    check("banned mint", scan_script(bytes([0x51, 0xF4])), ("banned", "OP_USDSOQ_MINT"))
    check("banned patagg", scan_script(bytes([0xFD])), ("banned", "OP_CHECKPATAGG"))
    check("banned rangeproof after push", scan_script(bytes([0x02, 0xAA, 0xBB, 0xFA])),
          ("banned", "OP_SOQUOBSCURA_RANGEPROOF"))
    check("0xf4 inside direct push is data", scan_script(bytes([0x01, 0xF4, 0x51])), ("ok", None))
    check("0xfd inside PUSHDATA1 is data", scan_script(bytes([0x4C, 0x02, 0xFD, 0xFC, 0x51])), ("ok", None))
    check("0xfa inside PUSHDATA2 is data", scan_script(bytes([0x4D, 0x01, 0x00, 0xFA])), ("ok", None))
    check("truncated PUSHDATA1", scan_script(bytes([0x4C])), ("parse_fail", 1))
    check("truncated push body", scan_script(bytes([0x05, 0x01])), ("parse_fail", 1))
    check("ordinary dilithium checksig", scan_script(bytes([0x76, 0xA9, 0x14] + [0] * 20 + [0x88, 0xAC])), ("ok", None))
    check("empty script", scan_script(b""), ("ok", None))
    # Whole-witness path: hash check plus scan on a synthetic v6 spend.
    ws = bytes([0x51, 0xF6])
    prog = hashlib.sha256(ws).digest()
    stack = ["aa" * 4, ws.hex(), "00" + "bb" * 8]
    check("v6 stack witnessScript position", classify_v6(stack, prog), ("banned", "OP_USDSOQ_FREEZE"))
    check("v6 hash mismatch detected", classify_v6(stack, b"\x00" * 32), ("hash_mismatch", None))
    check("v6 short stack detected", classify_v6([ws.hex()], prog), ("short_stack", None))
    # T3: the detector that gates the APO tightening must prove itself too.
    good_sig = "aa" * DILITHIUM_SIG_BYTES
    good_pk = "00" + "bb" * 1312
    check("t3 sighash_all", t3_classify([good_sig + "01", good_pk], None), ("checked", 0x01))
    check("t3 anyprevout", t3_classify([good_sig + "41", good_pk], None), ("checked", 0x41))
    check("t3 anyprevoutanyscript", t3_classify([good_sig + "42", good_pk], None), ("checked", 0x42))
    check("t3 anyonecanpay|apo masks to 0x41",
          t3_classify([good_sig + "c1", good_pk], None), ("checked", 0x41))
    check("t3 raw 1312-byte pubkey accepted",
          t3_classify([good_sig + "01", "bb" * 1312], None), ("checked", 0x01))
    # The false-positive vector this scoping exists to kill: a two-item v6
    # witness whose witnessScript happens to end in 0x41.
    check("t3 v6 prevout excluded", t3_classify([good_sig + "41", good_pk], 6),
          ("not_single_key", None))
    check("t3 v7 prevout is single-key", t3_classify([good_sig + "41", good_pk], 7),
          ("checked", 0x41))
    check("t3 v8 prevout is single-key", t3_classify([good_sig + "42", good_pk], 8),
          ("checked", 0x42))
    check("t3 short witnessScript is not a signature",
          t3_classify(["5141", good_pk], None), ("not_dilithium_shape", None))
    check("t3 wrong pubkey size rejected",
          t3_classify([good_sig + "41", "bb" * 33], None), ("not_dilithium_shape", None))
    check("t3 three-item stack is not single-key",
          t3_classify([good_sig + "41", good_pk, "00"], None), ("not_single_key", None))
    check("t3 empty sig", t3_classify(["", good_pk], None), ("not_single_key", None))
    check("t3 odd-length hex", t3_classify(["abc", good_pk], None), ("undecodable", None))
    # The verdict is the gate. Assert that EVERY tightening blocks the deploy
    # on its own -- the C1 defect was a hit list that was collected, printed
    # and then left out of this condition.
    ok_controls = {"a": True, "b": True}
    none = {name: [] for name in SCAN_TESTS}
    check("verdict passes when clean and proven",
          compute_verdict(none, ok_controls), ("PASS", 0))
    for name in SCAN_TESTS:
        hits = dict(none, **{name: [{"height": 1}]})
        got = compute_verdict(hits, ok_controls)
        check(f"verdict FAILs on a {name} hit alone", (got[1], name in got[0]), (2, True))
    check("verdict FAILs on an unproven instrument",
          compute_verdict(none, {"a": True, "b": False})[1], 3)
    check("a hit outranks an unproven instrument",
          compute_verdict(dict(none, T3=[{"height": 1}]), {"a": False})[1], 2)
    # The defect was at the CALL SITE, so assert the guard that makes a
    # forgotten detector loud instead of silent.
    for dropped in SCAN_TESTS:
        short = {k: v for k, v in none.items() if k != dropped}
        try:
            compute_verdict(short, ok_controls)
            check(f"verdict REFUSES a hits dict missing {dropped}", "accepted", "ValueError")
        except ValueError as e:
            check(f"verdict REFUSES a hits dict missing {dropped}", dropped in str(e), True)
    try:
        compute_verdict(dict(none, T9=[]), ok_controls)
        check("verdict REFUSES an unknown detector name", "accepted", "ValueError")
    except ValueError as e:
        check("verdict REFUSES an unknown detector name", "T9" in str(e), True)
    # F1 round 3, part 1: the match conditions that used to be inline glue in
    # main(). Review broke each of them and --selftest stayed green because
    # nothing here could reach them. They are now a table and a predicate.
    check("coinbase v10 routes to T2", coinbase_detector(10), "T2")
    check("coinbase v5 routes to T2b", coinbase_detector(5), "T2b")
    check("coinbase v1 is not a detector", coinbase_detector(1), None)
    check("coinbase v6 is not a detector", coinbase_detector(6), None)
    check("coinbase v9 is not a detector (already banned pre-branch)",
          coinbase_detector(9), None)
    check("every coinbase detector name is in SCAN_TESTS",
          set(COINBASE_BANNED_VERSIONS.values()) <= set(SCAN_TESTS), True)
    check("apo base 0x41 detected", is_apo_base(0x41), True)
    check("apo base 0x42 detected", is_apo_base(0x42), True)
    check("sighash_all is not apo", is_apo_base(0x01), False)
    check("sighash_single is not apo", is_apo_base(0x03), False)
    check("apo base set is exactly the two BIP 118 types",
          sorted(APO_BASE_TYPES), [0x41, 0x42])
    # T1's table needs the same pin, and needs it MORE than the other two:
    # its collection control cannot catch a dropped entry (see
    # collection_controls), so this is the only guard it has. Measured before
    # this check existed: deleting 0xF5, 0xF7 or 0xFC from BANNED left
    # SELFTEST OK (69 checks), exit 0, and a v6 spend carrying that opcode
    # scanned as "ok" with every collection control true and verdict PASS.
    # ⚠️ SCOPE: this pins BANNED against a literal in this file. It catches a
    # deletion or a typo here; it does NOT couple to interpreter.cpp. Keeping
    # the two lists in step is an allocation-time human step, recorded in
    # doc/specifications/WITNESS_VERSION_FORK_CLASS.md.
    check("banned opcode set is exactly interpreter.cpp's v6 ban list",
          [hex(op) for op in sorted(BANNED)],
          ["0xf4", "0xf5", "0xf6", "0xf7", "0xfa", "0xfc", "0xfd"])
    # The literal above is what catches a deletion. This loop is DERIVED from
    # BANNED and therefore cannot, but it proves every entry is reachable
    # through the GetOp walk rather than merely present in the dict.
    for op, name in sorted(BANNED.items()):
        check(f"scan_script detects {name} in a v6 witnessScript",
              scan_script(bytes([0x51, op])), ("banned", name))

    # F1 round 3, part 2: the collection side of the wiring. Breaking a detector's
    # match condition or its append leaves the verdict side untouched, so these
    # cross-checks are what catch it. Drive them agreeing and disagreeing.
    agree_hits = {"T1": [1, 2], "T2": [1], "T2b": [], "T3": [1, 1, 1]}
    agree_v6 = {"banned": 1, "parse_fail": 1}
    agree_cb = {10: 1, 5: 0}
    agree_t3 = {"base_types": {"0x1": 90, "0x41": 2, "0x42": 1}}
    cc = collection_controls(agree_hits, agree_v6, agree_cb, agree_t3)
    check("collection controls agree on a consistent scan", all(cc.values()), True)
    for name, broken in [
        ("T1", {**agree_hits, "T1": []}),
        ("T2", {**agree_hits, "T2": []}),
        ("T3", {**agree_hits, "T3": []}),
    ]:
        got = collection_controls(broken, agree_v6, agree_cb, agree_t3)
        check(f"collection control catches a {name} detector that stopped appending",
              all(got.values()), False)
    # A detector that stops MATCHING leaves its counter behind too: T2b's
    # counter is the coinbase-version histogram, which is built earlier.
    got = collection_controls(agree_hits, agree_v6, {10: 1, 5: 3}, agree_t3)
    check("collection control catches a T2b detector that stopped matching",
          got["t2b_hits_match_coinbase_v5_count"], False)
    # F4: --partial must not fake full_range_scanned.
    partial_controls = {"a": True, "full_range_scanned": False}
    check("partial range FAILs without the override",
          compute_verdict(none, partial_controls)[1], 3)
    got = compute_verdict(none, partial_controls, allow_partial=True)
    check("partial range passes WITH the override but says so",
          (got[1], "PARTIAL" in got[0]), (0, True))
    check("the override waives ONLY full_range_scanned",
          compute_verdict(none, {"a": False, "full_range_scanned": False},
                          allow_partial=True)[1], 3)
    check("an unmet control is named in the verdict",
          "t3_saw_sighash_all" in compute_verdict(
              none, {"t3_saw_sighash_all": False})[0], True)
    # F10: v5 is the version T2b exists for and was not in the version table.
    check("v5 program", witness_version("5520" + h32)[0], 5)
    check("v7 program", witness_version("5720" + h32)[0], 7)
    check("v8 program", witness_version("5820" + h32)[0], 8)
    if fails:
        print("SELFTEST FAIL\n  " + "\n  ".join(fails))
        return 1
    print(f"SELFTEST OK ({count[0]} checks)")
    return 0


def classify_v6(stack_hex, program):
    """Consensus layout: witness[n-2] is the witnessScript, witness[n-1] the
    Dilithium pubkey. Fewer than 2 items is WITNESS_PROGRAM_MISMATCH."""
    if len(stack_hex) < 2:
        return "short_stack", None
    ws = bytes.fromhex(stack_hex[-2])
    if hashlib.sha256(ws).digest() != program:
        return "hash_mismatch", None
    return scan_script(ws)


class Rpc:
    def __init__(self, conf_path, datadir):
        user = pw = None
        port = 28332  # stagenet default (src/chainparamsbase.cpp)
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "rpcuser":
                    user = v
                elif k == "rpcpassword":
                    pw = v
                elif k == "rpcport":
                    port = int(v)
        if user is None or pw is None:
            cookie = os.path.join(datadir, "stagenet", ".cookie")
            with open(cookie) as f:
                user, pw = f.read().strip().split(":", 1)
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
        self.port = port
        self.conn = None

    def call(self, batch):
        body = json.dumps([{"jsonrpc": "1.0", "id": i, "method": m, "params": p}
                           for i, (m, p) in enumerate(batch)])
        for attempt in range(5):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
                self.conn.request("POST", "/", body,
                                  {"Authorization": self.auth, "Content-Type": "application/json"})
                resp = self.conn.getresponse()
                data = resp.read()
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}: {data[:200]!r}")
                out = json.loads(data)
                out.sort(key=lambda r: r["id"])
                for r in out:
                    if r.get("error"):
                        raise RuntimeError(f"RPC error: {r['error']}")
                return [r["result"] for r in out]
            except (http.client.HTTPException, OSError, RuntimeError) as e:
                self.conn = None
                if attempt == 4:
                    raise
                time.sleep(2 * (attempt + 1))
                sys.stderr.write(f"rpc retry {attempt + 1}: {e}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--conf", default="/root/.soqucoin/soqucoin.conf")
    ap.add_argument("--datadir", default="/root/.soqucoin")
    ap.add_argument("--from", dest="h_from", type=int, default=0)
    ap.add_argument("--partial", action="store_true",
                    help="allow a PASS over a partial range. The deploy gate must "
                         "NOT use this: a partial scan cannot clear the chain.")
    ap.add_argument("--to", dest="h_to", type=int, default=None, help="inclusive; default = tip at start")
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if selftest() != 0:
        return 1

    rpc = Rpc(args.conf, args.datadir)
    info = rpc.call([("getblockchaininfo", [])])[0]
    tip_h, tip_hash = info["blocks"], info["bestblockhash"]
    h_to = tip_h if args.h_to is None else min(args.h_to, tip_h)
    if args.h_from > h_to:
        sys.exit(f"empty range: --from {args.h_from} is above --to/tip {h_to}; nothing scanned, no verdict")
    if args.h_from > 0:
        sys.stderr.write("NOTE: --from > 0 only sees v6 outputs CREATED at or after --from; "
                         "spends of earlier v6 outputs are not classified. Use a full run for the gate.\n")

    # outpoint -> (version, program) for every witness program v2..v16 still unspent
    progs = {}
    created = {}          # version -> count of outputs created (all versions, positive control)
    spent = {}            # version -> count of spends seen (v2..v16 only, from progs)
    cb_outputs = {}       # version -> coinbase output count ("nonprogram" for the rest)
    v6 = {"spends": 0, "ok": 0, "banned": 0, "parse_fail": 0, "hash_mismatch": 0, "short_stack": 0}
    # T3: two-item (single-key path) witnesses, by base sighash type of stack[0].
    t3 = {"checked": 0, "not_single_key": 0, "not_dilithium_shape": 0,
          "undecodable": 0, "apo": 0, "apoanyscript": 0, "base_types": {}}
    hits = {name: [] for name in SCAN_TESTS}
    anomalies, txs_total = [], 0
    t0 = time.time()

    for start in range(args.h_from, h_to + 1, args.batch):
        heights = list(range(start, min(start + args.batch, h_to + 1)))
        hashes = rpc.call([("getblockhash", [h]) for h in heights])
        blocks = rpc.call([("getblock", [hh, 2]) for hh in hashes])
        for h, blk in zip(heights, blocks):
            if blk["height"] != h:
                raise RuntimeError(f"batch ordering broken: asked for height {h}, got {blk['height']}")
            for tx in blk["tx"]:
                txs_total += 1
                is_cb = "coinbase" in tx["vin"][0]
                for vout in tx["vout"]:
                    spk = vout["scriptPubKey"]["hex"]
                    wp = witness_version(spk)
                    ver = wp[0] if wp else None
                    if is_cb:
                        key = ver if ver is not None else "nonprogram"
                        cb_outputs[key] = cb_outputs.get(key, 0) + 1
                        cb_detector = coinbase_detector(ver)
                        if cb_detector:
                            hits[cb_detector].append(
                                {"height": h, "txid": tx["txid"], "n": vout["n"]})
                    if ver is not None:
                        created[ver] = created.get(ver, 0) + 1
                        if ver >= 2:
                            progs[(tx["txid"], vout["n"])] = (ver, wp[1])
                if is_cb:
                    continue
                for vin in tx["vin"]:
                    key = (vin["txid"], vin["vout"])
                    # T3 is evaluated BEFORE the progs.pop below so it can see
                    # the prevout's witness version and exclude v2+ shapes that
                    # are not the single-key path. v0/v1 are never in progs.
                    tracked = progs.get(key)
                    status, base = t3_classify(vin.get("txinwitness", []),
                                               tracked[0] if tracked else None)
                    t3[status] += 1
                    if status == "undecodable":
                        anomalies.append({"height": h, "txid": tx["txid"],
                                          "status": "t3_sig_undecodable"})
                    elif status == "checked":
                        t3["base_types"][hex(base)] = t3["base_types"].get(hex(base), 0) + 1
                        if is_apo_base(base):
                            t3["apo" if base == 0x41 else "apoanyscript"] += 1
                            hits["T3"].append({"height": h, "txid": tx["txid"],
                                            "prevout": f'{vin["txid"]}:{vin["vout"]}',
                                            "sighash": hex(base)})
                    entry = progs.pop(key, None)
                    if entry is None:
                        continue
                    ver, program = entry
                    spent[ver] = spent.get(ver, 0) + 1
                    if ver != 6:
                        continue
                    v6["spends"] += 1
                    status, detail = classify_v6(vin.get("txinwitness", []), program)
                    v6[status] += 1
                    rec = {"height": h, "txid": tx["txid"], "prevout": f"{key[0]}:{key[1]}",
                           "status": status, "detail": detail}
                    if status in ("banned", "parse_fail"):
                        hits["T1"].append(rec)       # the tightening: accepted then, rejected now
                    elif status != "ok":
                        anomalies.append(rec)        # rejected before #83 too: scanner or RPC defect
        done = heights[-1] - args.h_from + 1
        if (heights[-1] + 1) % 5000 == 0 or heights[-1] == h_to:
            rate = done / max(time.time() - t0, 1e-9)
            sys.stderr.write(f"height {heights[-1]}/{h_to}  txs={txs_total}  v6spends={v6['spends']}  "
                             + " ".join(f"{n.lower()}={len(hits[n])}" for n in SCAN_TESTS)
                             + f"  {rate:.0f} blk/s\n")

    result = {
        "scan": "additive-asset genesis door pre-deploy gate (bead nydh)",
        "node_subversion": rpc.call([("getnetworkinfo", [])])[0]["subversion"],
        "chain": info["chain"],
        "tip_at_start": {"height": tip_h, "hash": tip_hash},
        "range": {"from": args.h_from, "to": h_to, "blocks": h_to - args.h_from + 1},
        "txs_total": txs_total,
        "outputs_created_by_version": {str(k): v for k, v in sorted(created.items())},
        "spends_by_version_v2plus": {str(k): v for k, v in sorted(spent.items())},
        "coinbase_outputs_by_version": {str(k): v for k, v in sorted(cb_outputs.items(), key=lambda kv: str(kv[0]))},
        "unspent_v2plus_programs_at_end": len(progs),
        "T1_v6_witnessScript": v6,
        "T1_hits": hits["T1"],
        "T2_coinbase_v10_hits": hits["T2"],
        "T2b_coinbase_v5_hits": hits["T2b"],
        "T3_single_key_path_sighash": t3,
        "T3_apo_on_single_key_path_hits": hits["T3"],
        "instrument_anomalies": anomalies,
    }
    # The instrument must prove it saw the chain before its zero counts mean
    # anything: a v6 spend actually decoded, the version classifier saw the v7
    # outputs USDSOQ has on stagenet, and coinbases parsed as witness programs.
    # A hash mismatch or short stack on an ACCEPTED v6 spend cannot be a
    # tightening (both were rejected before #83), so it is a scanner or RPC
    # defect and also blocks the verdict.
    controls = {
        # A partial range can satisfy every other control and still miss the
        # block that matters. A PASS asserts something about the WHOLE chain.
        # This control stays HONEST under --partial: the override is applied in
        # compute_verdict and recorded separately, so the artifact never
        # asserts a range it did not scan.
        "full_range_scanned": args.h_from == 0 and h_to == tip_h,
        "v6_spends_seen_nonzero": v6["spends"] > 0,
        # Was an int, so compute_verdict's isinstance(v, bool) filter skipped
        # it and it gated nothing despite sitting in this dict.
        "v6_outputs_created_nonzero": created.get(6, 0) > 0,
        "v7_outputs_created_nonzero": created.get(7, 0) > 0,
        # T3's zero is only a result if the detector actually decoded
        # signatures on the single-key path in this range. Seeing SIGHASH_ALL
        # is the stronger form: it proves the byte being read really is a
        # hashtype, not merely that the loop ran.
        "t3_single_key_spends_checked_nonzero": t3["checked"] > 0,
        "t3_saw_sighash_all": t3["base_types"].get("0x1", 0) > 0,
        "coinbase_v0_or_v1_seen": (cb_outputs.get(0, 0) + cb_outputs.get(1, 0)) > 0,
        "no_instrument_anomalies": not anomalies,
    }
    controls.update(collection_controls(hits, v6, cb_outputs, t3))
    result["positive_controls"] = controls
    result["partial_override_used"] = bool(args.partial)
    verdict, code = compute_verdict(hits, controls, allow_partial=args.partial)
    result["verdict"] = verdict
    result["elapsed_s"] = round(time.time() - t0, 1)
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
