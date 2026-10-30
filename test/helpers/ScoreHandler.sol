// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {ScoreHarness} from "./ScoreHarness.sol";

/// @dev Inputs are generated from an independent accepted-call history, not from the board's getters.
/// Expected failures are caught and checked exactly. Every unexpected revert fails the campaign.
contract ScoreHandler is ScoreHarness {
    struct ExpectedBest {
        uint64 score;
        bytes32 runId;
    }

    SqueekSupplyBoard public immutable board;
    address[4] public actors;
    bytes32[3] public challenges;
    bytes32[3] public expectedConfig;
    ExpectedBest[4][3] internal expectedBest;
    bytes32[] internal attemptedRuns;
    bytes32[] internal acceptedRuns;
    mapping(bytes32 => bool) public expectedPinned;

    uint256[3] internal keys = [KEY_A, KEY_B, KEY_C];
    address[3] internal signers;
    uint256 internal currentKeyIndex;
    uint256 internal previousKey;
    address public expectedOwner;
    address public expectedPendingOwner;
    address public expectedSigner;
    address public expectedPreviousSigner;
    uint64 public expectedPreviousValidUntil;
    uint256 public actions;
    uint256 public successfulPins;
    uint256 public rejectedCalls;
    uint256 public rotations;
    uint256 public timeAdvances;

    constructor(SqueekSupplyBoard target) {
        board = target;
        expectedOwner = WORKFLOW_OWNER;
        for (uint256 i; i < 4; ++i) {
            actors[i] = vm.addr(uint256(keccak256(abi.encode("invariant player", i))));
        }
        for (uint256 i; i < 3; ++i) {
            challenges[i] = keccak256(abi.encode("invariant challenge", i));
            signers[i] = vm.addr(keys[i]);
        }
        expectedSigner = signers[0];
    }

    function _fresh(uint256 actorIndex, uint256 challengeIndex, uint256 step, uint256 variant)
        internal
        returns (Attestation memory a)
    {
        a.runId = bytes32(attemptedRuns.length + 1);
        attemptedRuns.push(a.runId);
        a.player = actors[actorIndex];
        a.challengeId = challenges[challengeIndex];
        a.configHash = expectedConfig[challengeIndex];
        if (a.configHash == bytes32(0)) {
            a.configHash = keccak256(abi.encode("configuration", challengeIndex, variant % 3));
        }
        // At depth 64 this cannot approach uint64.max; full-width values are exercised in fuzz/unit tests.
        a.score = expectedBest[challengeIndex][actorIndex].score + uint64(_bound(step, 1, 1_000_000_000));
        a.deliveries = uint32(variant);
        a.deadline = uint64(vm.getBlockTimestamp() + variant % (1 days + 1));
    }

    function _accept(uint256 actorIndex, uint256 challengeIndex, Attestation memory a, uint256 key) internal {
        _submit(board, a, _sign(board, key, a));
        require(!expectedPinned[a.runId], "handler attempted to accept a used run");
        require(a.score > expectedBest[challengeIndex][actorIndex].score, "handler did not generate an improvement");
        expectedBest[challengeIndex][actorIndex] = ExpectedBest(a.score, a.runId);
        if (expectedConfig[challengeIndex] == bytes32(0)) expectedConfig[challengeIndex] = a.configHash;
        expectedPinned[a.runId] = true;
        acceptedRuns.push(a.runId);
        successfulPins++;
    }

    function _expectRejected(Attestation memory a, bytes memory signature, bytes memory reason) internal {
        bytes32 beforeState = _scoreState(board, a);
        vm.prank(a.player);
        (bool success, bytes memory result) = address(board).call(_calldata(a, signature));
        require(!success, "invalid score was accepted");
        require(keccak256(result) == keccak256(reason), "unexpected score rejection reason");
        require(_scoreState(board, a) == beforeState, "rejected score changed state");
        rejectedCalls++;
    }

    function submitImprovement(uint256 actorSeed, uint256 challengeSeed, uint256 step, uint256 variant) external {
        actions++;
        uint256 actorIndex = actorSeed % 4;
        uint256 challengeIndex = challengeSeed % 3;
        Attestation memory a = _fresh(actorIndex, challengeIndex, step, variant);
        _accept(actorIndex, challengeIndex, a, keys[currentKeyIndex]);
    }

    function submitInvalid(uint256 actorSeed, uint256 challengeSeed, uint256 failureSeed) external {
        actions++;
        uint256 actorIndex = actorSeed % 4;
        uint256 challengeIndex = challengeSeed % 3;
        uint256 failure = failureSeed % 10;
        Attestation memory a = _fresh(actorIndex, challengeIndex, 1, failureSeed);
        bytes memory reason;
        bytes memory signature;
        if (failure == 0) {
            a.deadline = uint64(vm.getBlockTimestamp() - 1);
            reason = abi.encodeWithSelector(SqueekSupplyBoard.Expired.selector);
        } else if (failure == 1) {
            a.score = expectedBest[challengeIndex][actorIndex].score;
            reason = abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector);
        } else if (failure == 2) {
            // Once locked, a *validly signed* incompatible configuration must still fail.
            a.configHash = expectedConfig[challengeIndex] == bytes32(0)
                ? bytes32(0)
                : expectedConfig[challengeIndex] ^ bytes32(uint256(1));
            reason = abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector);
        } else if (failure == 3) {
            signature = _sign(board, UNAUTHORIZED_KEY, a);
            reason = abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector);
        } else if (failure == 4) {
            signature = _sign(board, keys[currentKeyIndex], a);
            a.player = actors[(actorIndex + 1) % 4];
            // Keep the altered player's score above their existing best so authentication is reached.
            // The signature was made for a different sender, independently of the new score below.
            a.score = expectedBest[challengeIndex][(actorIndex + 1) % 4].score + 1;
            reason = abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector);
        } else if (failure == 5) {
            a.configHash = bytes32(0);
            reason = abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector);
        } else if (failure == 6) {
            signature = _sign(board, keys[currentKeyIndex], a);
            a.score += 1;
            reason = abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector);
        } else if (failure == 7) {
            reason = abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", uint256(0));
        } else if (failure == 8) {
            a.challengeId = bytes32(0);
            reason = abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector);
        } else {
            a.runId = bytes32(0);
            reason = abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector);
        }
        if (signature.length == 0 && failure != 7) signature = _sign(board, keys[currentKeyIndex], a);
        _expectRejected(a, signature, reason);
    }

    function replayAccepted(uint256 runSeed, uint256 actorSeed, uint256 challengeSeed) external {
        actions++;
        Attestation memory a = _fresh(actorSeed % 4, challengeSeed % 3, 1, 0);
        a.runId = acceptedRuns[runSeed % acceptedRuns.length];
        // Re-signing for another caller/challenge must not bypass the global run-ID lock.
        _expectRejected(
            a, _sign(board, keys[currentKeyIndex], a), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector)
        );
    }

    function rotateSigner(uint256 seed) external {
        actions++;
        uint256 nextIndex = (currentKeyIndex + 1 + seed % 2) % 3;
        vm.prank(expectedOwner);
        board.setSigner(signers[nextIndex]);
        previousKey = keys[currentKeyIndex];
        expectedPreviousSigner = expectedSigner;
        expectedPreviousValidUntil = uint64(vm.getBlockTimestamp() + 86400);
        currentKeyIndex = nextIndex;
        expectedSigner = signers[nextIndex];
        rotations++;
    }

    function usePreviousSigner(uint256 actorSeed, uint256 challengeSeed) external {
        actions++;
        uint256 actorIndex = actorSeed % 4;
        uint256 challengeIndex = challengeSeed % 3;
        Attestation memory a = _fresh(actorIndex, challengeIndex, 1, 0);
        if (previousKey != 0 && vm.getBlockTimestamp() <= expectedPreviousValidUntil) {
            _accept(actorIndex, challengeIndex, a, previousKey);
        } else {
            uint256 key = previousKey == 0 ? UNAUTHORIZED_KEY : previousKey;
            _expectRejected(a, _sign(board, key, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        }
    }

    function revokePrevious() external {
        actions++;
        vm.prank(expectedOwner);
        (bool success, bytes memory reason) =
            address(board).call(abi.encodeCall(SqueekSupplyBoard.revokePreviousSigner, ()));
        if (previousKey == 0) {
            require(
                !success
                    && keccak256(reason)
                        == keccak256(abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector)),
                "empty revocation did not reject"
            );
            rejectedCalls++;
        } else {
            require(success, "owner could not revoke previous signer");
            previousKey = 0;
            expectedPreviousSigner = address(0);
            expectedPreviousValidUntil = 0;
        }
    }

    function advanceTime(uint256 elapsed) external {
        actions++;
        vm.warp(vm.getBlockTimestamp() + _bound(elapsed, 0, 2 days));
        timeAdvances++;
    }

    function nominateOwner(uint256 seed) external {
        actions++;
        address next = seed % 5 == 4 ? address(0) : actors[seed % 5];
        vm.prank(expectedOwner);
        board.transferOwnership(next);
        expectedPendingOwner = next;
    }

    function acceptOwner(uint256 seed) external {
        actions++;
        address candidate = actors[seed % 4];
        vm.prank(candidate);
        (bool success, bytes memory reason) = address(board).call(abi.encodeWithSignature("acceptOwnership()"));
        if (candidate == expectedPendingOwner) {
            require(success, "nominated owner could not accept");
            expectedOwner = candidate;
            expectedPendingOwner = address(0);
        } else {
            require(!success, "unnominated caller accepted ownership");
            require(
                keccak256(reason)
                    == keccak256(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", candidate)),
                "wrong ownership rejection"
            );
            rejectedCalls++;
        }
    }

    function unauthorizedAdministration(uint256 seed, uint256 actionSeed) external {
        actions++;
        uint256 actorIndex = seed % 4;
        while (actors[actorIndex] == expectedOwner) actorIndex = (actorIndex + 1) % 4;
        address caller = actors[actorIndex];
        uint256 action = actionSeed % 4;
        bytes memory callData;
        if (action == 0) callData = abi.encodeCall(SqueekSupplyBoard.setSigner, (caller));
        if (action == 1) callData = abi.encodeCall(SqueekSupplyBoard.revokePreviousSigner, ());
        if (action == 2) callData = abi.encodeWithSignature("transferOwnership(address)", caller);
        if (action == 3) callData = abi.encodeWithSignature("renounceOwnership()");
        vm.prank(caller);
        (bool success, bytes memory reason) = address(board).call(callData);
        require(!success, "unauthorized administration succeeded");
        bytes memory expected = action == 3
            ? abi.encodeWithSelector(SqueekSupplyBoard.RenounceDisabled.selector)
            : abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", caller);
        require(keccak256(reason) == keccak256(expected), "unexpected administrative rejection");
        rejectedCalls++;
    }

    function assertScoreHistory() external view {
        for (uint256 c; c < 3; ++c) {
            require(
                board.challengeConfig(challenges[c]) == expectedConfig[c],
                "configuration lock differs from first accepted attestation"
            );
            for (uint256 p; p < 4; ++p) {
                (uint64 score, bytes32 run) = board.best(challenges[c], actors[p]);
                ExpectedBest memory expected = expectedBest[c][p];
                require(score == expected.score, "best decreased, changed player, or lacks valid attestation");
                require(run == expected.runId, "best run does not match accepted improvement");
                if (score > 0) require(board.pinned(run), "best refers to an unconsumed run");
            }
        }
    }

    function assertRunHistory() external view {
        require(successfulPins > 0 && successfulPins == acceptedRuns.length, "successful path was not exercised");
        for (uint256 i; i < attemptedRuns.length; ++i) {
            bytes32 run = attemptedRuns[i];
            require(board.pinned(run) == expectedPinned[run], "run reopened or failed attempt consumed a run");
        }
        require(!board.pinned(bytes32(0)), "zero run accepted");
        require(board.challengeConfig(bytes32(0)) == bytes32(0), "zero challenge accepted");
    }

    function assertAdministration() external view {
        require(board.owner() == expectedOwner && expectedOwner != address(0), "owner changed without handoff");
        require(board.pendingOwner() == expectedPendingOwner, "pending owner changed unexpectedly");
        require(board.signer() == expectedSigner, "signer changed without owner authorization");
        require(board.previousSigner() == expectedPreviousSigner, "unexpected previous signer");
        require(board.previousSignerValidUntil() == expectedPreviousValidUntil, "unexpected grace window");
    }
}
