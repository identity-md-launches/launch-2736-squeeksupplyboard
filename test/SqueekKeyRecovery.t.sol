// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {BoardTestBase, ScoreVm} from "./helpers/ScoreHarness.sol";

/// @dev Covers the emergency rotation (`replaceSigner`), the retired-key lock remedy (`clearChallengeConfig`)
/// and the rejection of re-setting the active signer.
contract SqueekKeyRecoveryTest is BoardTestBase {
    bytes32 internal constant OTHER_CONFIG = keccak256("replacement ss-2.0.0 configuration");

    function _unauthorized(address caller) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", caller);
    }

    function _replace(uint256 key) internal {
        vm.prank(WORKFLOW_OWNER);
        board.replaceSigner(vm.addr(key));
    }

    function _clear(bytes32 challengeId) internal {
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(challengeId);
    }

    function _signerState() internal view returns (bytes32) {
        return keccak256(abi.encode(board.signer(), board.previousSigner(), board.previousSignerValidUntil()));
    }

    // ---------------------------------------------------------------- setSigner(same)

    function testSetSignerRejectsTheActiveSignerAndKeepsTheGraceWindow() public {
        _rotate(KEY_B);
        uint64 cutoff = board.previousSignerValidUntil();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        bytes32 beforeState = _signerState();
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.setSigner(vm.addr(KEY_B));
        require(_signerState() == beforeState, "rejected re-set changed signer state");
        require(board.previousSignerValidUntil() == cutoff, "retry extended or cut the grace window");
        // The replaced key keeps validating exactly up to its original cutoff.
        vm.warp(cutoff);
        Attestation memory a = _attestation(1, 1);
        _submit(board, a, _sign(board, KEY_A, a));
        _assertBest(board, a);
    }

    function testSetSignerRejectsTheInitialSignerBeforeAnyRotation() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.setSigner(vm.addr(KEY_A));
        require(board.previousSigner() == address(0) && board.previousSignerValidUntil() == 0, "grace created");
    }

    function testRotatingBackToThePreviousSignerSwapsThem() public {
        _rotate(KEY_B);
        _rotate(KEY_A);
        require(board.signer() == vm.addr(KEY_A) && board.previousSigner() == vm.addr(KEY_B), "swap failed");
        Attestation memory a = _attestation(1, 1);
        _submit(board, a, _sign(board, KEY_B, a));
        _assertBest(board, a);
    }

    /// @dev Documented in `setSigner`'s NatSpec: only the immediately previous key is honoured.
    function testSecondPlannedRotationInsideGraceHonoursOnlyTheLatestReplacedKey() public {
        _rotate(KEY_B);
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        _rotate(KEY_C);
        require(board.previousSigner() == vm.addr(KEY_B), "latest replaced key not kept");
        require(board.previousSignerValidUntil() == vm.getBlockTimestamp() + 1 days, "grace not restarted");
        Attestation memory a = _attestation(1, 1);
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        _submit(board, a, _sign(board, KEY_B, a));
        _assertBest(board, a);
    }

    // ---------------------------------------------------------------- replaceSigner

    function testReplaceSignerInvalidatesTheReplacedKeyImmediately() public {
        vm.recordLogs();
        _replace(KEY_B);
        ScoreVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1, "only SignerChanged expected without a previous signer");
        require(logs[0].topics[0] == keccak256("SignerChanged(address,address)"), "wrong event");
        require(keccak256(logs[0].data) == keccak256(abi.encode(vm.addr(KEY_A), vm.addr(KEY_B))), "wrong event data");
        require(board.signer() == vm.addr(KEY_B), "signer not installed");
        require(board.previousSigner() == address(0) && board.previousSignerValidUntil() == 0, "grace granted");

        Attestation memory a = _attestation(1, 1);
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        _submit(board, a, _sign(board, KEY_B, a));
        _assertBest(board, a);
    }

    function testReplaceSignerAlsoRevokesAnUnexpiredPreviousSigner() public {
        _rotate(KEY_B);
        vm.recordLogs();
        _replace(KEY_C);
        ScoreVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 2, "revocation and change expected");
        require(logs[0].topics[0] == keccak256("PreviousSignerRevoked(address)"), "revocation not first");
        require(keccak256(logs[0].data) == keccak256(abi.encode(vm.addr(KEY_A))), "wrong revoked key");
        require(keccak256(logs[1].data) == keccak256(abi.encode(vm.addr(KEY_B), vm.addr(KEY_C))), "wrong change");
        require(board.previousSigner() == address(0) && board.previousSignerValidUntil() == 0, "grace survived");

        bytes memory bad = abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector);
        Attestation memory a = _attestation(1, 1);
        _reject(board, a, _sign(board, KEY_A, a), bad);
        _reject(board, a, _sign(board, KEY_B, a), bad);
        _submit(board, a, _sign(board, KEY_C, a));
        _assertBest(board, a);
        // Nothing left to revoke.
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
    }

    function testReplaceSignerRejectsZeroAndActiveSignerWithoutSideEffects() public {
        _rotate(KEY_B);
        bytes32 beforeState = _signerState();
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.replaceSigner(address(0));
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.replaceSigner(vm.addr(KEY_B));
        require(_signerState() == beforeState, "rejected replacement revoked or changed keys");
        // The previous signer is still honoured because the failed calls revoked nothing.
        Attestation memory a = _attestation(1, 1);
        _submit(board, a, _sign(board, KEY_A, a));
        _assertBest(board, a);
    }

    function testReplaceSignerToThePreviousSignerLeavesOnlyThatKey() public {
        _rotate(KEY_B);
        _replace(KEY_A);
        require(board.signer() == vm.addr(KEY_A) && board.previousSigner() == address(0), "unexpected keys");
        Attestation memory a = _attestation(1, 1);
        _reject(board, a, _sign(board, KEY_B, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        _submit(board, a, _sign(board, KEY_A, a));
        _assertBest(board, a);
    }

    function testReplaceSignerPreservesScoresConsumedRunsAndLocks() public {
        Attestation memory a = _attestation(1, 7);
        _pin(a);
        _replace(KEY_B);
        _assertBest(board, a);
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(KEY_A), "lock signer rewritten");
        Attestation memory replay = _attestation(1, 8);
        _reject(
            board, replay, _sign(board, KEY_B, replay), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector)
        );
    }

    function testOnlyOwnerCanReplaceSigner() public {
        address[4] memory callers = [player, vm.addr(KEY_A), address(this), address(0)];
        for (uint256 i; i < callers.length; ++i) {
            vm.expectRevert(_unauthorized(callers[i]));
            vm.prank(callers[i]);
            board.replaceSigner(vm.addr(KEY_B));
        }
        // A pending owner has no authority until it accepts.
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(player);
        vm.expectRevert(_unauthorized(player));
        vm.prank(player);
        board.replaceSigner(vm.addr(KEY_B));
        require(board.signer() == vm.addr(KEY_A), "unauthorized replacement");
    }

    // ---------------------------------------------------------------- challengeConfigSigner

    function testFirstPinRecordsTheRecoveringKeyAndLaterPinsDoNotOverwriteIt() public {
        _rotate(KEY_B);
        // First pin of the challenge is signed by the previous (grace) key.
        Attestation memory a = _attestation(1, 1);
        _submit(board, a, _sign(board, KEY_A, a));
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(KEY_A), "lock signer not recorded");
        Attestation memory b = _attestation(2, 2);
        _submit(board, b, _sign(board, KEY_B, b));
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(KEY_A), "later pin overwrote lock signer");
    }

    function testRejectedPinsRecordNoLockSigner() public {
        Attestation memory a = _attestation(1, 1);
        _reject(
            board, a, _sign(board, UNAUTHORIZED_KEY, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector)
        );
        require(board.challengeConfigSigner(CHALLENGE) == address(0), "rejected pin recorded a signer");
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
    }

    // ---------------------------------------------------------------- clearChallengeConfig

    function testLockByTheCurrentSignerCannotBeCleared() public {
        _pin(_attestation(1, 1));
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == CONFIG, "active lock cleared");
    }

    function testLockByAnUnexpiredPreviousSignerCannotBeClearedUntilGraceEnds() public {
        _pin(_attestation(1, 1));
        _rotate(KEY_B);
        uint64 cutoff = board.previousSignerValidUntil();
        vm.warp(cutoff);
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
        vm.warp(uint256(cutoff) + 1);
        _clear(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == bytes32(0), "lock not cleared after grace");
        require(board.challengeConfigSigner(CHALLENGE) == address(0), "lock signer not cleared");
    }

    function testLeakedKeyLockIsClearableAfterReplacementAndAcceptsANewConfiguration() public {
        // A leaked key pre-locks a future challenge to a junk configuration.
        bytes32 future = keccak256("future daily challenge");
        Attestation memory junk = Attestation(
            bytes32(uint256(1)), future, keccak256("junk"), otherPlayer, 1, 0, uint64(vm.getBlockTimestamp())
        );
        _submit(board, junk, _sign(board, KEY_A, junk));
        _replace(KEY_B);

        vm.recordLogs();
        _clear(future);
        ScoreVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1, "one event expected");
        require(logs[0].topics[0] == keccak256("ChallengeConfigCleared(bytes32,bytes32,address)"), "wrong event");
        require(logs[0].topics[1] == future, "wrong challenge topic");
        require(keccak256(logs[0].data) == keccak256(abi.encode(keccak256("junk"), vm.addr(KEY_A))), "wrong data");

        // The pinned record and consumed run of the leaked key are kept, as documented.
        (uint64 score, bytes32 run) = board.best(future, otherPlayer);
        require(score == 1 && run == junk.runId && board.pinned(junk.runId), "historical pin changed");

        // The new signer can lock the real configuration; the junk one is no longer enforced.
        Attestation memory real = Attestation(
            bytes32(uint256(2)), future, OTHER_CONFIG, player, 5, 4, uint64(vm.getBlockTimestamp() + 1 days)
        );
        _submit(board, real, _sign(board, KEY_B, real));
        _assertBest(board, real);
        require(board.challengeConfigSigner(future) == vm.addr(KEY_B), "new lock signer not recorded");
        // And it is now locked again: the junk configuration is refused, and the new lock is not clearable.
        Attestation memory again =
            Attestation(bytes32(uint256(3)), future, keccak256("junk"), player, 6, 4, real.deadline);
        _reject(
            board,
            again,
            _sign(board, KEY_B, again),
            abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector)
        );
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(future);
    }

    function testLockByARevokedPreviousSignerIsClearable() public {
        _pin(_attestation(1, 1));
        _rotate(KEY_B);
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
        _clear(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == bytes32(0), "lock not cleared");
    }

    function testLockBecomesUnclearableWhenItsKeyIsReinstated() public {
        _pin(_attestation(1, 1));
        _replace(KEY_B);
        _replace(KEY_A);
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
        // Reinstated as the previous signer through a planned rotation it is again protected.
        _rotate(KEY_B);
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
    }

    function testClearRejectsAnUnlockedChallengeAndASecondClear() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(bytes32(0));
        _pin(_attestation(1, 1));
        _replace(KEY_B);
        _clear(CHALLENGE);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.clearChallengeConfig(CHALLENGE);
    }

    function testClearDoesNotAllowLowerScoresOrReplayedRuns() public {
        Attestation memory a = _attestation(1, 100);
        _pin(a);
        _replace(KEY_B);
        _clear(CHALLENGE);
        // Strict improvement still applies to records made under the cleared configuration.
        Attestation memory lower = Attestation(bytes32(uint256(2)), CHALLENGE, OTHER_CONFIG, player, 100, 0, a.deadline);
        _reject(board, lower, _sign(board, KEY_B, lower), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
        Attestation memory replay =
            Attestation(bytes32(uint256(1)), CHALLENGE, OTHER_CONFIG, player, 101, 0, a.deadline);
        _reject(
            board, replay, _sign(board, KEY_B, replay), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector)
        );
        require(board.challengeConfig(CHALLENGE) == bytes32(0), "failed pins relocked the challenge");
    }

    function testOnlyOwnerCanClearALock() public {
        _pin(_attestation(1, 1));
        _replace(KEY_B);
        address[4] memory callers = [player, vm.addr(KEY_A), vm.addr(KEY_B), address(this)];
        for (uint256 i; i < callers.length; ++i) {
            vm.expectRevert(_unauthorized(callers[i]));
            vm.prank(callers[i]);
            board.clearChallengeConfig(CHALLENGE);
        }
        require(board.challengeConfig(CHALLENGE) == CONFIG, "unauthorized clear");
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzClearabilityFollowsKeyServiceStatus(uint32 elapsed, bool revoke) public {
        _pin(_attestation(1, 1));
        _rotate(KEY_B);
        uint64 cutoff = board.previousSignerValidUntil();
        if (revoke) {
            vm.prank(WORKFLOW_OWNER);
            board.revokePreviousSigner();
        }
        vm.warp(vm.getBlockTimestamp() + _bound(elapsed, 0, 3 days));
        bool inService = !revoke && vm.getBlockTimestamp() <= cutoff;
        vm.prank(WORKFLOW_OWNER);
        (bool ok, bytes memory reason) =
            address(board).call(abi.encodeCall(SqueekSupplyBoard.clearChallengeConfig, (CHALLENGE)));
        if (inService) {
            require(!ok, "lock of an in-service key cleared");
            require(
                keccak256(reason) == keccak256(abi.encodeWithSelector(SqueekSupplyBoard.LockSignerActive.selector)),
                "wrong rejection"
            );
            require(board.challengeConfig(CHALLENGE) == CONFIG, "lock changed on failure");
        } else {
            require(ok, "lock of a retired key not clearable");
            require(board.challengeConfig(CHALLENGE) == bytes32(0), "lock not cleared");
        }
    }
}
