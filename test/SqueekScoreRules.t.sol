// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {BoardTestBase, ScoreVm} from "./helpers/ScoreHarness.sol";

contract SqueekScoreRulesTest is BoardTestBase {
    function testMinimumScoreAndZeroDeliveriesEmitBackendCompatibleEvent() public {
        Attestation memory a = _attestation(1, 1);
        a.deliveries = 0;
        _pinAndCheckEvent(a);
    }

    function _pinAndCheckEvent(Attestation memory a) internal {
        bytes memory signature = _sign(board, KEY_A, a);
        vm.recordLogs();
        _submit(board, a, signature);
        _assertBest(board, a);
        ScoreVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1, "one score event required");
        require(logs[0].emitter == address(board), "wrong emitter");
        require(logs[0].topics.length == 4, "wrong indexed fields");
        require(
            logs[0].topics[0] == keccak256("ScorePinned(address,bytes32,bytes32,bytes32,uint64,uint32)"),
            "event ABI changed"
        );
        require(logs[0].topics[1] == bytes32(uint256(uint160(a.player))), "wrong event player");
        require(logs[0].topics[2] == a.challengeId, "wrong event challenge");
        require(logs[0].topics[3] == a.runId, "wrong event run");
        require(
            keccak256(logs[0].data) == keccak256(abi.encode(a.configHash, a.score, a.deliveries)), "wrong event payload"
        );
    }

    function testMaximumScoreDeliveriesAndDeadlineArePreserved() public {
        Attestation memory a = _attestation(1, type(uint64).max);
        a.deliveries = type(uint32).max;
        a.deadline = type(uint64).max;
        _pinAndCheckEvent(a);
        a.runId = bytes32(uint256(2));
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
    }

    function testZeroScoreCannotCreateARecordOrLockAChallenge() public {
        Attestation memory a = _attestation(1, 0);
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
        require(!board.pinned(a.runId) && board.challengeConfig(CHALLENGE) == bytes32(0), "zero score consumed state");
        a.score = 1;
        _pin(a);
    }

    function testZeroIdentifiersAreRejectedIndividually() public {
        for (uint256 field; field < 3; ++field) {
            Attestation memory a = _attestation(1, 1);
            if (field == 0) a.runId = bytes32(0);
            if (field == 1) a.challengeId = bytes32(0);
            if (field == 2) a.configHash = bytes32(0);
            _reject(
                board,
                a,
                _sign(board, KEY_A, a),
                abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector)
            );
        }
        _pin(_attestation(1, 1));
    }

    function testDeadlineIsInclusiveAndExpiredRunCanBeRetriedWithNewAttestation() public {
        Attestation memory a = _attestation(1, 100);
        a.deadline = uint64(vm.getBlockTimestamp());
        _pin(a);

        a.runId = bytes32(uint256(2));
        a.score = 101;
        bytes memory expired = _sign(board, KEY_A, a);
        vm.warp(vm.getBlockTimestamp() + 1);
        _reject(board, a, expired, abi.encodeWithSelector(SqueekSupplyBoard.Expired.selector));
        a.deadline = uint64(vm.getBlockTimestamp());
        _pin(a);
    }

    function testZeroDeadlineIsExpired() public {
        Attestation memory a = _attestation(1, 1);
        a.deadline = 0;
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.Expired.selector));
    }

    function testBestOnlyIncreasesAndEveryPreviouslyAcceptedRunRemainsConsumed() public {
        Attestation memory first = _attestation(1, 100);
        _pin(first);
        Attestation memory second = _attestation(2, 101);
        _pin(second);
        require(board.pinned(first.runId), "improvement reopened old run");
        first.score = 102;
        _reject(
            board, first, _sign(board, KEY_A, first), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector)
        );
        _assertBest(board, second);
    }

    function testRunIdCannotBeReusedByAnotherPlayerOrChallengeEvenWithFreshSignature() public {
        Attestation memory a = _attestation(1, 100);
        _pin(a);
        a.player = otherPlayer;
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector));
        a.challengeId = keccak256("another challenge");
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector));
        a.runId = bytes32(uint256(2));
        _pin(a);
    }

    function testConfigurationIsGlobalToChallengeButBestIsPerPlayer() public {
        Attestation memory a = _attestation(1, 100);
        _pin(a);
        Attestation memory b = _attestation(2, 1);
        b.player = otherPlayer;
        b.configHash = keccak256("conflicting config");
        _reject(
            board, b, _sign(board, KEY_A, b), abi.encodeWithSelector(SqueekSupplyBoard.InvalidConfiguration.selector)
        );
        b.configHash = CONFIG;
        _pin(b);
        _assertBest(board, a);
        b.runId = bytes32(uint256(3));
        b.challengeId = keccak256("independent challenge");
        b.configHash = keccak256("independent config");
        b.player = player;
        _pin(b);
        _assertBest(board, a);
    }

    function testRejectedSignatureCannotPreemptTheFirstConfigurationLock() public {
        Attestation memory a = _attestation(1, 100);
        a.configHash = keccak256("unauthorized first config");
        _reject(
            board, a, _sign(board, UNAUTHORIZED_KEY, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector)
        );
        a.configHash = CONFIG;
        _pin(a);
    }

    function testEqualOrLowerScoreRejectsAValidSignatureWithoutConsumingRun() public {
        Attestation memory a = _attestation(1, 100);
        _pin(a);
        a.runId = bytes32(uint256(2));
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
        a.score = 99;
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
        a.score = 101;
        _pin(a);
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzAcceptedScoreMatchesAttestation(uint64 score, uint32 deliveries, uint64 remaining) public {
        Attestation memory a = _attestation(1, uint64(_bound(score, 1, type(uint64).max)));
        a.deliveries = deliveries;
        a.deadline = uint64(_bound(remaining, vm.getBlockTimestamp(), type(uint64).max));
        _pinAndCheckEvent(a);
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzOnlyStrictImprovementsChangeBest(uint64 first, uint64 candidate) public {
        Attestation memory a = _attestation(1, uint64(_bound(first, 1, type(uint64).max)));
        _pin(a);
        Attestation memory b = _attestation(2, candidate);
        if (candidate > a.score) {
            _pin(b);
            require(board.pinned(a.runId), "old run reopened");
        } else {
            _reject(board, b, _sign(board, KEY_A, b), abi.encodeWithSelector(SqueekSupplyBoard.NotHigher.selector));
            _assertBest(board, a);
        }
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzDeadlineBoundary(uint64 deadline, uint8 direction) public {
        Attestation memory a = _attestation(1, 1);
        a.deadline = uint64(_bound(deadline, 1, type(uint64).max - 1));
        uint256 mode = direction % 3;
        vm.warp(uint256(a.deadline) + mode - 1);
        if (mode == 2) {
            _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.Expired.selector));
        } else {
            _pin(a);
        }
    }

    function testPayableAttemptsRevertWithoutConsumingValidAttestation() public {
        Attestation memory a = _attestation(1, 1);
        bytes memory signature = _sign(board, KEY_A, a);
        vm.deal(player, 1 ether);
        vm.prank(player);
        (bool success,) = address(board).call{value: 1}(_calldata(a, signature));
        require(!success && !board.pinned(a.runId), "pinScore accepted payment");
        require(address(board).balance == 0 && player.balance == 1 ether, "value was retained");
        vm.prank(player);
        (success,) = address(board).call{value: 1}("");
        require(!success && address(board).balance == 0, "plain ETH accepted");
        _pin(a);
    }
}
