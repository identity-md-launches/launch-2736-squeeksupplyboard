# SqueekSupplyBoard adversarial tests

Run the accepted tests and this contribution offline from the repository root:

```sh
sh test/check.sh
```

The root `foundry.toml` selects `contracts/test`. Plain `forge test` therefore runs
the accepted suite only. The runner checks both directories separately using the
process-local `FOUNDRY_TEST` setting, without editing configuration. It also runs
`forge build`, pins the assignment's fuzz seed, and writes generated files only
under `test/scratch`. No additional dependency, RPC, key, FFI, environment mutation
cheatcode, or downloaded library is needed. The existing Solidity 0.8.26 compiler
and committed OpenZeppelin sources are sufficient.

To run just these tests directly:

```sh
FOUNDRY_TEST=test \
FOUNDRY_OUT=test/scratch/out \
FOUNDRY_CACHE_PATH=test/scratch/cache \
FOUNDRY_FUZZ_SEED=0x80e5d2ec1a22300e4a3b356a910d5e0498d6fef211dbe8ed7b21918d50efa1d6 \
forge test --offline --no-match-path 'test/scratch/**'
```

## Coverage and properties

| Suite | Guarantees checked |
| --- | --- |
| `SqueekScoreRules.t.sol` | Strict improvements; per-player/per-challenge isolation; permanent, global run-ID consumption; first successful configuration lock; failed submissions leave state intact; zero/one/maximum values; inclusive deadlines; nonpayable pinning; backend-compatible event fields. |
| `SqueekSignatures.t.sol` | Every signed field and every EIP-712 domain field is bound; chain/contract/player replay fails; personal-sign payloads fail; invalid lengths, recovery IDs, zero recovery and high-S malleability fail; unauthorized submissions cannot burn valid runs. |
| `SqueekAdministration.t.sol` | Approved public constructor addresses; zero-address rejection; separation of signer and owner; pending/replaced/former-owner privileges; cancellation and disabled renunciation; rotation/revocation events; grace cutoff and deadline interactions; preserved scores after rotation/revocation. |
| `SqueekStateful.t.sol` | All player records, challenge locks, consumed run IDs, ownership, signer and grace state agree with independent accepted-call history after random operations. |

Each stateless fuzz property runs 1,000 cases using inline Foundry settings.
The stateful campaign runs 256 sequences of 64 calls, with four players, three
challenges and three signing keys. It mixes valid improvements, ten kinds of
invalid submissions, replays, signer rotations, grace-window probes, revocation,
time changes, ownership nominations/acceptance and unauthorized administration.
Only the ten intended handler selectors are targeted. Expected failures check
exact revert bytes; unexpected handler reverts fail the campaign.

The ghost model is updated from accepted inputs rather than copied from contract
getters. It tracks the best record for all twelve player/challenge pairs, the first
accepted configuration, and every generated run ID, including rejected attempts.
A seeded successful run makes historical properties meaningful immediately;
`afterInvariant` verifies that random actions actually ran. A deterministic handler
test exercises every rejection mode, successful and unsuccessful handoffs, current
and previous signers, expiry, and revocation with explicit success/failure counts.

## Discovery scope

The five supplied discovery perspectives were applied locally:

1. **Conservation:** no ETH/token balances, debts, shares, fees or payouts exist.
   There is no custody conservation equation to test. Historical run consumption
   and record isolation are checked instead; no claim is made that forced ETH
   transfers are impossible.
2. **Round trips and boundaries:** score/deadline retain `uint64` and deliveries
   retain `uint32`; zero, one, maxima and exact time cutoffs are explicit cases.
   There is no conversion, rounding or withdraw/deposit pair.
3. **State transitions:** the workflow's single-use run IDs, strict improvements
   and one configuration per challenge are required properties
   (`src/SqueekSupplyBoard.sol:91-108`). Invalid attempts cannot establish a lock.
4. **Adversarial operations:** signatures cannot be borrowed across players,
   contracts or chains; unauthorized or stale keys cannot create records; valid
   fresh attestations remain submit-able through ownership and signer changes
   subject to the documented signer window (`src/SqueekSupplyBoard.sol:59-79,99-113`).
5. **Protocol-specific checks:** this is an EIP-712 scoreboard, so the independent
   type/domain literals and event schema match `server/chain.js`, including domain
   version `2`. No vault, token, pool, oracle or external-protocol assumptions apply.

The signature fixtures are deterministic test credentials, never production keys.
Constructor rehearsal uses the owner's and public signer's addresses from the
approved workflow. Tests do not modify source, ABI exports or the launch manifest.
No fork block was requested and the board calls no external protocol; all tests
run locally. Live API availability, deployment and frontend/IPFS checks belong to
later workflow stages and are not claimed by this suite.

## Reported defect

`.imd-findings.json` reports one low-severity availability defect: a second
`setSigner` call, including reapplying the current signer, discards the earlier
signer's still-active grace without revocation. An attestation with 86,398 seconds
left before its signed deadline then fails with `BadSignature`. The self-contained
proof is embedded in that report: its one-rotation control passes and its two
regression cases fail on the accepted source. It is kept outside the passing
submission suite rather than adding an assertion that this premature rejection is
correct. The existing `testSecondRotationDropsOlderSigner` documents the disputed
behavior and is unchanged.
