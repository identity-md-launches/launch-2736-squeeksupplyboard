# Adaptation for the IMD `evm_contracts` launch (Sepolia, chain id 11155111)

Scope of this step: make `SqueekSupplyBoard` launchable through the project factory with the smallest
change, fix the imported-code audit findings that reproduce, keep the Foundry suite green and export the
ABI. The manifest (`launch.json`) is written by the next step and is not part of this tree.

## Launch-compatibility review (no source change needed)

| Launch rule | State of the imported contract | Action |
| --- | --- | --- |
| Nonpayable constructor, static argument types, at most 16 | `constructor(address initialOwner, address initialSigner)`, nonpayable | none |
| Constructor must not call another contract or need code at an address | Only stores the signer and runs OpenZeppelin `EIP712`/`Ownable` constructors (pure string hashing and a storage write) | none; `contracts/test/SqueekSupplyBoardLaunch.t.sol` deploys it through a CREATE2 probe on an empty chain |
| Owner must not be `msg.sender` (factory) or `tx.origin` | Owner is the explicit `initialOwner` argument; the manifest fills it with the brief's owner `0x51404e4a699e4e338e143fb2a45c5cdc96392575` | none; tested in `testFactoryDeploymentDoesNotOwnTheBoard` |
| No minting, pausing, freezing, blacklisting, seizing, proxies, upgradeability, DELEGATECALL, CALLCODE, SELFDESTRUCT | Contract holds no funds and has none of these; runtime scanned for 0xF2/0xF4/0xFF reachable opcodes | none; tested in `testRuntimeIsBoundedAndHasNoEscapeOpcodes` |
| Only internal library functions | `ECDSA` and `EIP712` helpers are internal; bytecode has no link references | none |
| `bytecode_hash = "none"`, protected build files untouched | Already set in `foundry.toml` | none; `foundry.toml`, `remappings`, `lib/`, `package.json` and lockfile are unchanged |
| Contract name at most 32 characters | `SqueekSupplyBoard` (17) | none |
| No launch token, pool or distributor for a contracts-only launch | Project has none | none added |

The signer is an outside value from the brief (public signer `0x2Dc8205A9650faFB65B51aE25cC34cEfDEe08653`),
not an owner role, so it stays a plain constructor argument for the manifest step to fill as a static address.

## Changes

### 1. `src/SqueekSupplyBoard.sol`: signer rotation keeps the replaced signer valid for a grace window

- **Finding:** audit `9b6a6be7…` (low). `setSigner` made every unexpired attestation signed by the old key
  revert with `BadSignature`, adding a second expiry the brief does not state ("deadline must not be
  expired" is the validity rule). Reproduced in a scratch test before the change: an attestation signed at
  t=1000 with deadline t+86400 reverted right after `setSigner`.
- **Change:** `setSigner` now records the replaced key in `previousSigner` and sets
  `previousSignerValidUntil = block.timestamp + SIGNER_GRACE_PERIOD`. `pinScore` accepts a signature from
  the current signer, or from `previousSigner` while `block.timestamp <= previousSignerValidUntil`.
  `SIGNER_GRACE_PERIOD` is a constant of 86 400 seconds, the same 24-hour deadline the backend puts on every
  attestation (`server/app.js`), so no attestation that was valid when issued is cut off by a rotation.
  A second rotation drops the older key entirely (only one previous signer is kept).
- **Compromise path kept:** a new owner-only `revokePreviousSigner()` clears the window immediately and emits
  `PreviousSignerRevoked`, so a leaked key does not stay valid for 24 hours. It reverts with
  `InvalidConfiguration` when there is nothing to revoke.
- **ABI:** every existing function, event, error and the EIP-712 domain (`SqueekSupply`, version `2`) and
  `SCORE_TYPEHASH` are unchanged, so the backend and frontend encoders keep working. Additions only:
  `SIGNER_GRACE_PERIOD()`, `previousSigner()`, `previousSignerValidUntil()`, `revokePreviousSigner()`,
  event `PreviousSignerRevoked(address)`.
- **Tests:** `testRotationKeepsUnexpiredAttestationValid`, `testRotationAcceptsNewSignerImmediately`,
  `testPreviousSignerRejectedAfterGrace`, `testFuzzPreviousSignerWindow`, `testSecondRotationDropsOlderSigner`,
  `testRevokePreviousSignerCutsWindow`, `testRevokePreviousSignerOwnerOnly`,
  `testRevokePreviousSignerNothingToRevoke` in `contracts/test/SqueekSupplyBoard.t.sol`.

### 2. `src/SqueekSupplyBoard.sol`: `renounceOwnership()` disabled

- **Finding:** audit `d7ebb0e8…` (info). Inherited `Ownable.renounceOwnership` would leave the board with no
  owner, so `setSigner` could never be called again and a lost or leaked signing key could not be replaced.
  Reproduced in a scratch test: after `renounceOwnership`, `setSigner` reverted with
  `OwnableUnauthorizedAccount` and `owner()` was `address(0)`.
- **Change:** `renounceOwnership()` is overridden to revert with the new error `RenounceDisabled()`. The
  brief requires that "only the owner changes signer", which presumes an owner always exists.
  Two-step transfer (`transferOwnership` / `acceptOwnership`) is untouched.
- **Tests:** `testRenounceOwnershipDisabled`, `testRenounceOwnershipDisabledForEveryone`,
  `testTwoStepOwnershipTransferStillWorks`.

### 3. Audit finding `a407f86e…` (info, coverage record): no change

It reports no defect; it records what was read and verified and gives the manifest step its constructor
argument hints. Nothing to fix. The opcode scan and nonpayable constructor it describes are now kept as
regression tests in `contracts/test/SqueekSupplyBoardLaunch.t.sol`.

### 4. `contracts/test/SqueekSupplyBoard.t.sol`: reformatted and extended

The original eight tests are kept with the same assertions (`forge fmt` layout only) and the tests listed
above were added, plus constructor checks (`testConstructorRejectsZeroSigner`, `testConstructorRejectsZeroOwner`,
`testConstructorSetsOwnerAndSignerWithoutGrace`). No test was weakened or removed.

### 5. `contracts/test/SqueekSupplyBoardLaunch.t.sol`: new launch-shape tests

Deploys the board with CREATE2 from a probe contract so the constructor runs with a contract as
`msg.sender` (as the factory does), with the brief's owner and signer as arguments, and checks: owner is
the argument and not the factory or the test, signer is the argument, a payable deployment fails, the
runtime is within EIP-170 and has no reachable DELEGATECALL/CALLCODE/SELFDESTRUCT, and the EIP-712 domain
is `SqueekSupply` version `2` on chain id 11155111.

### 6. `docs/abi/SqueekSupplyBoard.json`: ABI export

Generated from the build (`forge inspect SqueekSupplyBoard abi --json`) for the frontend step.

### 7. `README.md`: documented signer rotation

Added a short subsection under "启用 Sepolia 存证" describing `SIGNER_GRACE_PERIOD`, `revokePreviousSigner`,
the disabled `renounceOwnership`, and where the ABI and this file live. No other project files, the game,
the server or the frontend were changed.

## Revision after independent review

The accepted work above was reopened by an independent review. Each finding below was reproduced in a
scratch test against the accepted code before any change (all three reproduced), then fixed with the
smallest additive change. No existing function, event, error, storage layout prefix, the EIP-712 domain
or `SCORE_TYPEHASH` changed; the backend (`server/chain.js`) and frontend encoders keep working unchanged.

### 8. `src/SqueekSupplyBoard.sol`: a lock written by a retired key can be cleared (review finding `4173811e…`, medium)

- **Finding:** `challengeConfig[challengeId]` is written by whichever authorised attestation lands first and
  nothing could ever clear it. Daily `challengeId`s are predictable (`server/challenges.js`), so a leaked key
  (the current signer, or a replaced one inside its grace window) could pre-lock future days to a junk
  `configHash`; after the key was revoked, every honest `pinScore` for those days reverted
  `InvalidConfiguration` forever. Reproduced with the reviewer's exact sequence (rotate A→B, A pre-locks
  2027-01-01 inside its grace window, revoke A, B's honest pin on that day reverts).
- **Change:** `pinScore` now records `challengeConfigSigner[challengeId] = recovered` when it first writes a
  lock (the lock itself is written only on first use; a later pin under the same lock neither rewrites nor
  re-attributes it). New owner-only `clearChallengeConfig(bytes32 challengeId)` deletes the lock and its
  signer record and emits `ChallengeConfigCleared(challengeId, configHash, lockedBy)`, but only while the
  recorded signer is retired: neither the current `signer` nor an unexpired `previousSigner`
  (otherwise `LockSignerActive()`; an unlocked challenge reverts `InvalidConfiguration()`). Locks written by a
  key the board still trusts stay immutable, so the brief's "each challengeId locks one configHash" holds for
  every attestation currently accepted; the owner's remedy exists only for keys already taken out of service.
  Clearing touches nothing else: spent `runId`s stay spent and `best` is unchanged.
- **Not changed:** `server/chain.js` still signs without reading `challengeConfig`; that is backend code
  outside this stage's scope and the on-chain remedy does not depend on it.
- **Tests:** `testPinRecordsLockSigner`, `testLeakedPreviousSignerLockIsClearedAndHonestPinSucceeds` (the
  reviewer's sequence end to end), `testLeakedCurrentSignerLockIsClearableAfterReplaceSigner`,
  `testClearChallengeConfigRefusedWhileLockingKeyInGrace`, `testFuzzClearChallengeConfigOnlyAfterLockingKeyRetired`,
  `testClearChallengeConfigOwnerOnly`, `testClearChallengeConfigNothingToClear`,
  `testClearedLockDoesNotReopenRunIdsOrLowerBest`.

### 9. `src/SqueekSupplyBoard.sol`: `setSigner` rejects the already active signer (review finding `92af57a0…`, low)

- **Finding:** `setSigner(signer)` was not a rotation yet overwrote `previousSigner` with the active key,
  discarding the grace window of the key actually replaced; its outstanding attestations then reverted
  `BadSignature`. Reproduced (second `setSigner(B)` at t+3600 set `previousSigner = B` and A's valid
  attestation reverted).
- **Change:** `setSigner` reverts `InvalidConfiguration()` when `newSigner == signer`, leaving
  `previousSigner`/`previousSignerValidUntil` untouched. Variant (b) of the finding, two genuine rotations
  inside one grace period dropping the older key, is the documented single-slot design
  (`testSecondRotationDropsOlderSigner`) and is unchanged; the NatSpec now says only the immediately previous
  key is honoured.
- **Tests:** `testSetSignerSameSignerRevertsAndKeepsGrace` (reviewer's sequence),
  `testSetSignerSameSignerRevertsWithoutPrevious`, `testSetSignerBackToPreviousIsARotation`.

### 10. `src/SqueekSupplyBoard.sol`: `replaceSigner` ends a leaked key in one transaction (review finding `a479cf11…`, low)

- **Finding:** after a compromise the natural call, `setSigner(newKey)`, still granted the leaked key a 24-hour
  window; ending it needed a second transaction (`revokePreviousSigner`), which cannot be sent first on the
  initial rotation, so the leaked key could land forged pins between the two receipts (or for 24 hours if the
  owner never sent the second one). Reproduced (K1-signed pin accepted right after `setSigner(K2)`).
- **Change:** new owner-only `replaceSigner(address newSigner)` installs the new signer and deletes
  `previousSigner`/`previousSignerValidUntil` in the same transaction, emitting `PreviousSignerRevoked` (when
  there was one) and `SignerChanged`. Same validation as `setSigner` (non-zero, not the active signer).
  `setSigner` remains the planned-rotation path with the grace window; `revokePreviousSigner` is kept.
- **Tests:** `testReplaceSignerRejectsReplacedKeyImmediately` (reviewer's sequence),
  `testReplaceSignerAlsoRevokesUnexpiredPreviousSigner`, `testReplaceSignerOwnerOnlyAndValidated`.

### 11. `docs/abi/SqueekSupplyBoard.json`, `README.md`

ABI regenerated from the build. Additions only: `challengeConfigSigner(bytes32)`, `clearChallengeConfig(bytes32)`,
`replaceSigner(address)`, event `ChallengeConfigCleared(bytes32,bytes32,address)`, error `LockSignerActive()`.
README's signer-rotation subsection documents the three new behaviours.

## Checks run

- `forge build` with the project's own `foundry.toml` (solc 0.8.26, cancun, optimizer 200, `bytecode_hash = "none"`): success.
- `forge test` with `FOUNDRY_FUZZ_SEED=0x80e5d2ec1a22300e4a3b356a910d5e0498d6fef211dbe8ed7b21918d50efa1d6`: 40 passed, 0 failed (36 in `SqueekSupplyBoard.t.sol`, 4 in `SqueekSupplyBoardLaunch.t.sol`). Tests use no environment variables and no shared state, so they pass in any order and in parallel.
- The launch-shape tests (`SqueekSupplyBoardLaunch.t.sol`) still pass after the revision: constructor unchanged
  (`owner`, `signer`), nonpayable, runtime within EIP-170 with no reachable DELEGATECALL/CALLCODE/SELFDESTRUCT.
- Slither and Mythril are not available on this machine and were not run; the reachable-opcode scan and the
  `forge lint` output were reviewed instead. Remaining lint notes are informational (`block.timestamp`
  comparisons, which the deadline and grace semantics require, and the pre-existing event-after-call note
  on the `ecrecover` precompile).

## Trust assumptions for review

- The owner (`0x51404e4a699e4e338e143fb2a45c5cdc96392575`) can rotate (`setSigner`), replace (`replaceSigner`)
  and revoke (`revokePreviousSigner`) signers, and clear a challenge lock written by a retired key
  (`clearChallengeConfig`); nothing else is privileged. The owner cannot alter or remove pins, change a lock
  written by a key still in service, or change a player's best.
- The signer is a backend key held outside this repository. A key rotated out with `setSigner` remains accepted
  for at most 24 hours unless the owner revokes it; a key removed with `replaceSigner` is rejected at once.
- The contract holds no ETH or tokens and has no payable function.
