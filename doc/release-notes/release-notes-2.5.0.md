Soqucoin Core 2.5.0
===================

Soqucoin Core 2.5.0 is the sixth freeze candidate for mainnet. It carries every
code change of the launch binary. A later release may add only the genesis
migration constants (see "Genesis migration arming" below); no other consensus or
binary change follows this release before launch.

Consensus rules are unchanged from 2.4.0 on every network. The consensus digest
pinned by `consensus_digest_tests` does not move in this release.

Upgrading
---------

Stop the running daemon, replace the binary, start it. No reindex is required.
Nodes run with `disablewallet=1`; there is no wallet data to back up.

Notable changes
---------------

### `getblockstats` counts fees over native SOQ only

`getblockstats` computed fees as inputs minus outputs across every asset in a
transaction. On blocks that carry a USDSOQ mint the output value exceeds the
input value in that asset, the subtraction went negative, and the daemon aborted
on an assertion. Any caller able to reach the RPC could stop a node by asking
for statistics on such a block.

Fee statistics now count native SOQ only. USDSOQ and BTCSOQ outputs are
conserved per asset and are excluded from the fee sum. The help text states
this. A regression suite covers the blocks that triggered the abort.

Operators who disabled explorers or other `getblockstats` callers as a
precaution can re-enable them once the node runs this release.

### Genesis migration arming: every height tier, and visible state

The genesis migration allocation rule (`hashMigrationOutputs`,
`nMigrationTotal`, `nMigrationHeight`) ships inert on every network: the hash is
null and the height is zero. This release changes how the constants are written
when a network is armed, and how a node reports them.

- The arming helper now walks every consensus height tier, so the tier that
  validates the armed height carries the constants. Previously the documented
  arming spot wrote only the first tier, which would have left the rule
  silently inert at heights above zero. A test pins the tier count per network
  and checks that every tier agrees.
- `getblockchaininfo` gains a `genesis_migration` object with `armed`,
  `height`, `hash_migration_outputs` and `total_sats`, read from the tier that
  validates the armed height. A node whose constants differ from the network's
  rejects the armed block, so operators can compare nodes before that height.
- The daemon logs one line at startup stating whether the rule is armed, with
  the height, total, output count and hash, or that it is inert.

On mainnet the constants stay null in this release. If a migration is armed it
happens at block 1 through a constants-only release on top of 2.5.0; no
post-genesis change to this rule is planned.

### Mining RPCs are gated by `-enablemining` (carried from 2.4.0, undocumented there)

Since 2.4.0 the work-serving RPCs (`getblocktemplate`, `generate`,
`generatetoaddress`, `createauxblock`, `getauxblock`, `submitauxblock`) refuse to
serve unless `-enablemining` is set. The default is `1` on every network except
mainnet, where the launch-period default is `0`. Pool and miner-facing nodes opt
in with `enablemining=1` in the configuration file. `submitblock`,
`getmininginfo` and `getnetworkhashps` are not gated; blocks still arrive over
the peer-to-peer network from any miner.

This is a launch-period default, documented here so that it is not mistaken for
a permission. It is an RPC-layer setting and does not change consensus:
solo-mined blocks that satisfy the rules are valid.

### Tests and documentation

- Reject-path tests for the introduced BTCSOQ and USDSOQ consensus reject
  strings.
- Bridge and gateway design documents are past-tensed as records; LatticeFold+
  is marked deprecated with SoquObscura as the successor; the project describes
  itself as based on Dogecoin Core.

Known limitations
-----------------

- The Linux release artifact is built on Ubuntu 22.04 and does not load on
  24.04 hosts (shared library versions). Fleet and exchange nodes build from the
  tag until a portable artifact ships.
- Verification-cost budgeting for post-quantum signatures is defined but not
  enforced; peer limits and ban thresholds are the launch mitigation. A fix is
  planned for the first post-launch release.

Credits
-------

Thanks to everyone who contributed to this release.
