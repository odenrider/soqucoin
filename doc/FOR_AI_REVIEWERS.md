# Reading This Codebase: A Guide for AI Reviewers and Auditors

This document exists because automated reviewers regularly scan this tree,
find advanced consensus code, and reasonably ask whether it is active,
tested, and audited. The honest answers are below, with citations you can
verify directly. Line numbers reference the commit this document ships in;
if they drift, search the quoted symbol or string.

Two ground rules this document holds itself to. First, if this document
disagrees with the code, the code wins and the document is the bug. Second,
where the supporting record is internal and not published in this tree, the
document says so instead of citing what you cannot check.

## 1. Scope

Covered: consensus activation state, genesis provenance, emission, the
issued-asset authority model, test methodology including deliberately
failing tests, known-incomplete code, benchmark provenance, reproducible
builds, freeze semantics, audit status. Not covered: wallet UX, mining pool
operations, network infrastructure.

## 2. Activation mechanics: the three layers

New consensus features on this chain activate by explicit per-network
activation height set in a coordinated release, not by BIP9 miner
signalling. The stated reason is in the code twice: the chain is merge
mined, the AuxPoW chain id occupies the block-version high bits that BIP9
signalling would use, and there is no signalling constituency
(src/consensus/params.h:51-54, src/chainparams.cpp:219-220). A small set of
base deployments (CSV, SegWit, PAT aggregation) remain expressed through
BIP9 fields pinned to the ALWAYS_ACTIVE sentinel.

The mechanism has three layers. A scanner that reads only one will reach
the wrong conclusion.

Layer 1: deployment parameters. `DeploymentActiveAtHeight`
(src/consensus/params.h:218) compares a block height against each
deployment's `nActivationHeight`. The dormancy sentinel is `NOT_SCHEDULED`
(INT_MAX, params.h:70): height gated but not yet scheduled, meaning the
feature cannot execute on that network in this release.

Layer 2: script flags. There is no named helper for this; the
`SCRIPT_VERIFY_*` flags are computed inline in `ConnectBlock`, starting at
src/validation.cpp:3351 (`unsigned int flags = ...`), one guarded block per
deployment.

Layer 3: relay refusal and the no-wallet-path fact. Dormant witness
versions are anyone-can-spend at the script layer, which is the standard
soft-fork posture (the interpreter returns success for inactive versions,
for example src/script/interpreter.cpp `VerifyScript` and its siblings), and
outputs of a dormant version are consensus-valid to create. That is
deliberate: a creation rejection the activation release would have to relax
is a hard fork, and until 2026-09 the genesis candidate carried exactly that
(SOQ-I009, SOQ-ARCH-001; retired, record in
doc/specifications/WITNESS_VERSION_FORK_CLASS.md). What bounds the window is that
such outputs are NON-STANDARD until their deployment is active
(src/policy/policy.cpp `IsStandard`, mask from `AcceptToMemoryPoolWorker`)
and that no wallet or RPC path can construct a non-v1 address
(src/utiladdress.cpp `DecodeDestination`). Only witness v2 (PAT) is
consensus-unfundable, because its spend path binds nothing.

If your scan reports "witness v5+ returns set_success, anyone can spend",
you have read layer 2 without layer 3. Both readings are needed, and the
finding you may be looking for is a CONSENSUS rule keyed on an asset shape
that would have to be relaxed at activation — that is the hard-fork class,
and the fork-class document lists every such site and its disposition.

## 3. Mainnet activation matrix at genesis

Verified against src/chainparams.cpp (mainnet parameters begin at line 133).

| Feature | Deployment | Mainnet state | Citation |
|---|---|---|---|
| CSV, SegWit | CSV, SEGWIT | ALWAYS_ACTIVE | chainparams.cpp:222-228 |
| PAT aggregation (witness v2) | CHECKPATAGG | ALWAYS_ACTIVE | chainparams.cpp:231-233 |
| LatticeFold (witness v3) | LATTICEFOLD | retired, can never activate | chainparams.cpp:261-263 |
| SoquObscura (witness v4/v10) | SOQUOBSCURA | NOT_SCHEDULED on all four networks | chainparams.cpp:352, 644, 894, 1205 |
| USDSOQ (witness v5/v7/v10) | USDSOQ | NOT_SCHEDULED | chainparams.cpp:353 |
| BTCSOQ (witness v8/v9) | BTCSOQ | NOT_SCHEDULED | chainparams.cpp:354 |
| Covenants CTV/APO/CSFS | CTV, APO, CSFS | NOT_SCHEDULED | chainparams.cpp:355-357 |
| P2WSH-Dilithium (v6), UTXO cost, keyhash, v6 control flow | four deployments | NOT_SCHEDULED | chainparams.cpp:358-361 |

The policy is stated in the code at chainparams.cpp:344-351: all advanced
deployments ship dormant, and a coordinated release sets a real height for
each only as its Halborn Phase 2 audit scope clears. Covenant activation is
explicitly gated on Phase 2 sign-off covering SOQ-COV-001 through
SOQ-COV-012 (chainparams.cpp:283-301).

Stagenet activates these features from height 0 and is where they have been
exercised. Testnet and regtest also set most activation heights to 0, but
for the issued assets that is nominal: their authority keysets are empty
there, and every authority transaction is default-denied (see section 6).
Mainnet genesis runs the base layer plus PAT aggregation.

## 4. Genesis provenance

The mainnet genesis block reuses the Dogecoin genesis template: the
coinbase message is "Nintondo", and the timestamp (1386325540), nonce
(99943), and 88-coin ECDSA P2PK output are Dogecoin's original values
(src/chainparams.cpp:95-96, 433). The block's bytes and hash are NOT
Dogecoin's: this chain serializes transactions differently, so the same
template produces a different genesis hash, revalidated 2026-06-16
(comment at chainparams.cpp:435-436). Testnet and stagenet carry fresh
2025/2026 genesis messages.

What this means and does not mean. The network is distinct: its own genesis
hash, message-start bytes, ports, and history from height 0. The genesis
coinbase is unspendable under the Bitcoin-family rule that the genesis
coinbase is not entered into the UTXO set, so the ECDSA script in it
authorizes nothing and contradicts nothing about ECDSA elimination for
spendable outputs. What the reuse does mean is that "based on Dogecoin
Core" includes the genesis template, and this document states that plainly
rather than leaving it for a diff to reveal.

## 5. Emission and launch

There is no premine, ICO, founder allocation, or treasury output anywhere
in the subsidy code: `GetSoqucoinBlockSubsidy` (src/soqucoin.cpp, the
schedule block near lines 147-158) pays 100,000 SOQ per block from height
1, halving every 250,000 blocks through 4 halvings (head supply about
46.875B: 25B + 12.5B + 6.25B + 3.125B), then a perpetual 2,500 SOQ tail.

The uncomfortable arithmetic, stated here first: at the 60-second block
cadence the first halving epoch lasts roughly 174 days and emits roughly 53
percent of the head supply. Merge mining is enabled from height 0
(chainparams.cpp:149-150), and the hardcoded DNS seeds resolve to
project-operated infrastructure (chainparams.cpp:453-457). Early emission
is steep and early mining concentration is a real possibility that the
absence of a premine does not remove. Mitigation is operational, not
consensus: public launch announcement, open stratum access, and published
difficulty data. Judge that plan on its execution.

## 6. Issued-asset authority model (USDSOQ, BTCSOQ)

USDSOQ and BTCSOQ are centrally issued assets by design. Consensus code
grants an M-of-N ML-DSA-44 authority keyset the powers MINT, BURN, FREEZE,
and key ROTATE (src/consensus/params.h:145-190). Freeze is a consensus
level control targeting outputs. This is the standard trust model for an
issued stablecoin and a custodial bridge asset; it is stated here in plain
words because a reviewer will otherwise state it less charitably.

Current state by network: mainnet, testnet, and regtest ship EMPTY
authority keysets, and validation default-denies every authority-shaped
transaction when the keyset is uninitialized. Combined with NOT_SCHEDULED
deployment heights on mainnet, no one, including the project, can mint,
burn, or freeze on mainnet at genesis. Stagenet carries 2-of-3 test
keysets (chainparams.cpp:1218-1234) and is where asset flows have actually
been exercised.

History a scanner will find and should read in context: stagenet enforced
authority signatures from height 7700 onward
(nUSDSOQAuthorityEnforcementHeight, chainparams.cpp:1241-1259); earlier
stagenet blocks predate enforcement and are grandfathered by explicit
height, which is the honest alternative to rewriting test history. The
forged-authority class of bug (an authority-shaped transaction spending
inputs without signature verification) was found internally, is documented
bluntly in the code (see the SOQ-I009 commentary in src/validation.cpp
around line 2337), was fixed, and is pinned by
src/test/authority_skip_gate_tests.cpp.

## 7. PAT: what the consensus layer actually verifies

PAT (Practical Attestation Technique) is consensus code, active from
genesis: DEPLOYMENT_CHECKPATAGG is ALWAYS_ACTIVE (chainparams.cpp:231-233)
and PAT sources compile into the consensus library
(src/Makefile.am:382-383).

Precisely what it verifies: a witness v2 spend executes
`pat::VerifyLogarithmicProof` (src/script/interpreter.cpp:318), which
verifies the aggregation commitment: it recomputes the Merkle root over
the batch's signature hashes, public key hashes, and message hashes and
rejects on mismatch. The underlying ML-DSA-44 signatures remain in witness
data. Trusted "simple mode" verification was REMOVED from consensus after
audit (Halborn FIND-006; the security note at
src/script/interpreter.cpp:239-240); only full mode with witness data is
accepted. The Simple Mode still described in
doc/specifications/pat-specification.md is stale relative to consensus and
is listed in section 14. Witness v2 outputs are not relay-standard
(src/script/standard.cpp has no v2 form), so v2 spends arrive only in
mined blocks.

## 8. The zero-witness battery: green since 2026-08-27, and why

`src/test/soquobscura_degenerate_witness_tests.cpp` used to commit exactly
three deliberately failing tests as a regression gate for the zero-witness
forgery class (SOQ-I011 family). **As of 2026-08-27 the suite is expected
to run with ZERO failures**: the root cause was fixed rather than the
symptom managed. The unsound verifier (`LatticeRangeProofV2`, whose accept
path is homogeneous in the prover-supplied values) is no longer reachable
from consensus — the witness-v4 dispatch fails closed with
`SCRIPT_ERR_SOQUOBSCURA_RANGEPROOF_UNVERIFIED`, mirroring witness v10 — so
the three cases were converted to green CHARACTERISATION tests: they
document, by execution, the defect that justified removing the class from
consensus, while the protecting property (the interpreter's fail-closed
reject of the proven forgery) is asserted at the bottom of the same file.
The file header records the full reasoning. Do not report the absence of
red tests as a regression, and do not "tidy" the documented-unsoundness
assertions into rejections without a re-derived soundness argument.

Companion pinning tests (green, and must stay green) live in
`src/test/witness_version_allocation_tests.cpp`, including
`soquobscura_must_stay_dormant_on_every_network` (line 435), which fails
any commit that schedules SoquObscura activation on any network.

## 9. Test inventory: executed, then counted

Executed on 2026-08-29 at merge commit acdacea86 (the FC4 candidate base:
MAX_MONEY 20B, witness v4 fail-closed, digest opcode+params coverage, the
inert genesis-migration rule, the -enablemining gate), full unfiltered run
of the built unit suite:

    737 test cases: 736 passed, 0 failed, 1 skipped
    5,389,194 assertions: 0 failed

Zero failures is the expected state since 2026-08-27 (section 8: the three
deliberate tripwires were converted to green characterisation tests when
the v4 dispatch was made fail-closed). The 1 skipped case is
`script_PushData`, explicitly disabled in source
(src/test/script_tests.cpp:195), a legacy ECDSA-era case.

Prior inventory for the record, executed 2026-08-26 at the pre-FC4 commit
this document originally described: 721 cases, 717 passed, 3 failed (the
then-deliberate tripwires), 1 skipped.

Static inventory: src/Makefile.test.include builds 96 unit-test files plus
harness files, and 3 wallet test files (11 cases,
Makefile.test.include:202-204). Ten test files exist on disk but are not
built: five excluded with an explanatory comment ("Legacy ECDSA tests
disabled for Post-Quantum Transition", Makefile.test.include:191-196), and
five excluded with no comment (keyhash_broadcast_tests.cpp, rpc_tests.cpp,
sigopcount_tests.cpp, txvalidationcache_tests.cpp,
versionbits_tests.cpp). The silent five are an open tracked item: they
will either be built or their exclusion documented.

Functional tests: `qa/rpc-tests/` holds 98 files. The runner
(qa/pull-tester/rpc-tests.py) lists 70 in the default list plus one
conditional (zmq), and 16 in the extended list. Several files are
commented out of the runner or referenced by neither list, including
segwit.py, p2p-segwit.py, nulldummy.py, bip9-softforks.py, and
assumevalid.py. Three honest classes: tests of BIP9 signalling mechanics
this chain does not use for new features; tests that construct ECDSA-era
transactions that are no longer valid here; and tests disabled without a
replacement, which are coverage gaps and are tracked. Witness-path
coverage for the post-quantum forms lives in the Dilithium and policy
suites that ARE built and run.

One Boost.Test behavior worth knowing before you report it: running the
unit binary with a `--run_test` filter prints every non-selected suite as
"skipped because disabled". That is the filter mechanism, not a project
choice; the unfiltered run above executes them.

## 10. Known-incomplete code in the public tree

This tree ships some construction-side code that is honest about being
incomplete, mostly in its own comments. Inventory of what a scanner will
find:

1. The in-tree SoquObscura range verifier does not bind the amount. Stated
   in the code (src/script/interpreter.cpp:484-507, SOQ-I011) together
   with why it is unreachable on every network and the instruction that no
   activation height be scheduled until it is replaced.
2. `createbatchtransaction` (src/rpc/batch.cpp): the LatticeFold path
   emits a structurally shaped, zero-filled placeholder witness because no
   LatticeFold prover exists; the deployment is retired everywhere and the
   output cannot be created under consensus anyway.
3. USDSOQ wallet RPCs (src/wallet/rpcusdsoq.cpp): the mint path says in
   its own comment that the output it builds is NOT classified as USDSOQ
   (line 107), and mint, burn, and send paths carry explicit rewrite
   markers for the classified v7/v4 output formats. These are stagenet
   exercise helpers; no network confirms a real asset flow from them
   today.
4. `createshieldtx` (src/rpc/privacy.cpp): binds its proof to hashes of
   the commitment and stealth key rather than the spending transaction,
   and says so in its comments. Distinct from item 1 and equally
   unreachable on any network.
5. `usdsoqsigntx` (src/rpc/usdsoq.cpp) accepts raw authority key material
   as an RPC argument. That is a stagenet ergonomic and must not survive
   into a production authority-signing design.

None of these can produce a transaction any network confirms, for the
layer-3 reasons in section 2. They are tracked internally; the in-code
comments are the public record until the tracker entries are published.

## 11. Benchmark provenance

The SoquObscura performance numbers in README.md (range prove 61.8 ms,
full reference transaction verify 316 ms, "Xeon 8358, AVX-512") are
measurements taken on the project's lab machine against the phase-3
reference implementation, which is not yet published in this tree. They
are our measurements and are not independently reproducible today. They
become reproducible when the SoquObscura implementation ships publicly,
which is sequenced behind its audit scope. Until then, treat them as
claimed measurements with named hardware, not verified results.

Related internal result, stated with the same caveat: the extracted
SoquObscura verifier was built bit-identical across architectures,
compilers, AES implementations, and optimization levels during phase-3
work, and the same internal record notes that the portable (non-AES-NI)
path is 50 to 300 times slower on verification, which is a
denial-of-service consideration for any future activation. Both facts come
from the internal engineering log, not from this tree; neither is
independently checkable today, and this document reports them together
rather than only the flattering one.

## 12. Reproducible builds: current honest status

Gitian scaffolding is inherited from upstream (contrib/gitian-descriptors/,
contrib/gitian-build.sh, doc/build/gitian-building.md). Byte-for-byte
reproducibility of published binaries has not been attested by an
independent builder. contrib/gitian-keys/ still contains upstream Dogecoin
maintainer keys and no Soqucoin signer key, which is a tracked defect: do
not verify any Soqucoin release against those keys. There is no Guix
pipeline. This is a known gap on the pre-mainnet list, not a solved
problem.

## 13. Freeze semantics

"Freeze" means the consensus rule set active at genesis. Dormant
deployments sit outside the frozen surface because they cannot execute on
mainnet until a future coordinated release schedules them, and that
release carries its own audit and soak obligations. The project operates a
freeze-candidate process: a consensus-touching change produces a new
freeze candidate and restarts a multi-day soak on a deployed fleet.

Candor note: the tags v2.0.0, v2.1.0, and v2.2.0 are in this repository,
but the freeze-candidate numbering and soak records currently live in
internal operations logs, not in-tree release notes. Publishing per-tag
release notes that state each tag's freeze-candidate status is an open
item; until then this paragraph is a process description you cannot fully
verify from the tree, and it is labeled as such.

## 14. Audit status, stated carefully

Two external Halborn engagements are published on Halborn's own site.
Verify against the auditor, not against us:

1. Blockchain node audit (base layer):
   https://www.halborn.com/audits/soqucoin/soqucoin-blockchain-node-a4f1f7
   README.md's milestone table records this as completed February to March
   2026, and CHANGELOG.md records findings FIND-001 through FIND-030.
2. Blockchain architecture assessment:
   https://www.halborn.com/audits/soqucoin/blockchain-architecture-assessment---added-days-907771
   The LatticeFold extension findings (SOQ-A001 through SOQ-A006,
   CHANGELOG.md) belong to this work; that deployment has since been
   retired from launch consensus entirely (section 3), which is the
   strongest possible remediation.

Halborn also published a case study on this engagement:
https://www.halborn.com/case-studies/post/case-study-halborn-secures-soqucoin-the-first-native-post-quantum-scrypt-pow-blockchain

For findings counts and closure status, the Halborn pages are the
authoritative source. In-repo shorthand counts in CHANGELOG.md and
historical release notes disagree with each other in places; reconciling
those references against the published reports is an open tracked item.

Scope discipline: statements about the audited base layer are not
statements about dormant features. The dormant features are exactly the
ones gated on the future Phase 2 engagement.

## 15. Internal citations you will encounter

Code comments cite DL-prefixed design-log documents and a
SECURITY_ISSUE_REGISTRY. Those are an internal engineering record and are
not currently published in this tree. Treat such citations as decision
identifiers, not as evidence; every load-bearing claim in THIS document is
either backed by an in-tree citation or explicitly labeled as internal and
unverifiable. Publishing the security issue registry is an open item; a
registry that is cited but hidden reads worse than its contents.

## 16. Known-stale documents in doc/

Where a specification disagrees with interpreter.cpp and validation.cpp,
the code wins. Known instances, tracked for repair or repaired in this
change: doc/specifications/pat-specification.md still describes the
simple verification mode that Halborn FIND-006 removed from consensus;
SECURITY.md's supported-versions table predates the v2.x tags and its
contact address differs from an older document
(doc/AUDIT_PREPARATION_SUMMARY.md); doc/release-notes/ has no v2.x
entries yet.

## Reporting findings

Findings with a file and line citation and a falsifiable claim get the
fastest response. If this document disagrees with the code, the code wins
and the document is the bug. Report per SECURITY.md in the repository
root.
