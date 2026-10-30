// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {BoardTestBase, ScoreVm} from "./helpers/ScoreHarness.sol";

contract SqueekAdministrationTest is BoardTestBase {
    function testConstructorRejectsZeroOwnerOrSigner() public {
        address signer = vm.addr(KEY_A);
        vm.expectRevert(abi.encodeWithSignature("OwnableInvalidOwner(address)", address(0)));
        new SqueekSupplyBoard(address(0), signer);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        new SqueekSupplyBoard(WORKFLOW_OWNER, address(0));
    }

    function testApprovedConstructorAddressesWorkWithoutExternalContracts() public {
        require(WORKFLOW_OWNER.code.length == 0 && WORKFLOW_SIGNER.code.length == 0, "fixture must have no code");
        SqueekSupplyBoard deployed = new SqueekSupplyBoard(WORKFLOW_OWNER, WORKFLOW_SIGNER);
        require(deployed.owner() == WORKFLOW_OWNER && deployed.signer() == WORKFLOW_SIGNER, "launch privileges changed");
        require(deployed.owner() != address(this), "deployer captured ownership");
    }

    function testZeroSignerRejectionPreservesCurrentAndPreviousSignerWindow() public {
        _rotate(KEY_B);
        uint64 cutoff = board.previousSignerValidUntil();
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.setSigner(address(0));
        require(board.signer() == vm.addr(KEY_B), "current signer changed on failure");
        require(board.previousSigner() == vm.addr(KEY_A), "previous signer changed on failure");
        require(board.previousSignerValidUntil() == cutoff, "grace window changed on failure");
        _pin(_attestation(1, 1));
    }

    function testScoreSignerHasNoAdministrativeAuthority() public {
        address signer = vm.addr(KEY_A);
        bytes memory reason = abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", signer);
        vm.expectRevert(reason);
        vm.prank(signer);
        board.setSigner(otherPlayer);
        vm.expectRevert(reason);
        vm.prank(signer);
        board.transferOwnership(otherPlayer);
        vm.expectRevert(reason);
        vm.prank(signer);
        board.revokePreviousSigner();
    }

    function testPendingOwnerCannotAdministerAndReplacedNomineeCannotAccept() public {
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(player);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.setSigner(otherPlayer);
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(otherPlayer);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.acceptOwnership();
        require(
            board.owner() == WORKFLOW_OWNER && board.pendingOwner() == otherPlayer,
            "failed acceptance changed ownership"
        );
        vm.prank(otherPlayer);
        board.acceptOwnership();
        require(board.owner() == otherPlayer && board.pendingOwner() == address(0), "handoff did not complete");
    }

    function testCancelOwnershipNominationKeepsCurrentOwnersControl() public {
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(player);
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(address(0));
        require(
            board.owner() == WORKFLOW_OWNER && board.pendingOwner() == address(0), "cancellation renounced ownership"
        );
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.acceptOwnership();
        _rotate(KEY_B);
    }

    function testOwnerCannotRenounceDuringPendingHandoff() public {
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(player);
        vm.expectRevert(SqueekSupplyBoard.RenounceDisabled.selector);
        vm.prank(WORKFLOW_OWNER);
        board.renounceOwnership();
        require(board.owner() == WORKFLOW_OWNER && board.pendingOwner() == player, "renunciation changed ownership");
        _rotate(KEY_B);
    }

    function testFormerOwnerCannotRotateOrRevokeButSuccessorCan() public {
        _rotate(KEY_B);
        vm.prank(WORKFLOW_OWNER);
        board.transferOwnership(player);
        vm.prank(player);
        board.acceptOwnership();
        bytes memory reason = abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", WORKFLOW_OWNER);
        vm.expectRevert(reason);
        vm.prank(WORKFLOW_OWNER);
        board.setSigner(otherPlayer);
        vm.expectRevert(reason);
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
        vm.prank(player);
        board.revokePreviousSigner();
        address next = vm.addr(KEY_C);
        vm.prank(player);
        board.setSigner(next);
        require(board.signer() == next, "successor cannot rotate signer");
    }

    function testRotationAndRevocationEventsIdentifyTheAffectedKeys() public {
        address oldSigner = vm.addr(KEY_A);
        address newSigner = vm.addr(KEY_B);
        vm.recordLogs();
        _rotate(KEY_B);
        ScoreVm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(board), "wrong rotation emitter");
        require(
            logs[0].topics.length == 1 && logs[0].topics[0] == keccak256("SignerChanged(address,address)"),
            "rotation event ABI changed"
        );
        require(keccak256(logs[0].data) == keccak256(abi.encode(oldSigner, newSigner)), "wrong rotated keys");
        vm.recordLogs();
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
        logs = vm.getRecordedLogs();
        require(logs.length == 1 && logs[0].emitter == address(board), "wrong revocation emitter");
        require(
            logs[0].topics.length == 1 && logs[0].topics[0] == keccak256("PreviousSignerRevoked(address)"),
            "revocation event ABI changed"
        );
        require(keccak256(logs[0].data) == keccak256(abi.encode(oldSigner)), "wrong revoked key");
    }

    function testGraceDoesNotOverrideAttestationDeadline() public {
        Attestation memory a = _attestation(1, 1);
        a.deadline = uint64(vm.getBlockTimestamp() + 10);
        bytes memory signature = _sign(board, KEY_A, a);
        _rotate(KEY_B);
        vm.warp(uint256(a.deadline) + 1);
        require(vm.getBlockTimestamp() < board.previousSignerValidUntil(), "not within grace");
        _reject(board, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.Expired.selector));
    }

    function testPreviouslyPinnedRunCannotReplayAfterRotationOrRevocation() public {
        Attestation memory a = _attestation(1, 1);
        _pin(a);
        _rotate(KEY_B);
        a.score = 2;
        _reject(board, a, _sign(board, KEY_B, a), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector));
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
        _reject(board, a, _sign(board, KEY_B, a), abi.encodeWithSelector(SqueekSupplyBoard.AlreadyPinned.selector));
    }

    function testRevocationIsImmediateButDoesNotUndoScoresOrConfiguration() public {
        Attestation memory a = _attestation(1, 100);
        _pin(a);
        _rotate(KEY_B);
        Attestation memory b = _attestation(2, 101);
        bytes memory oldSignature = _sign(board, KEY_A, b);
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
        _reject(board, b, oldSignature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        _assertBest(board, a);
        _submit(board, b, _sign(board, KEY_B, b));
        _assertBest(board, b);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(WORKFLOW_OWNER);
        board.revokePreviousSigner();
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzGraceWindowBoundary(uint32 elapsed) public {
        uint256 start = vm.getBlockTimestamp();
        _rotate(KEY_B);
        require(board.SIGNER_GRACE_PERIOD() == 86400, "grace no longer matches backend TTL");
        require(board.previousSignerValidUntil() == start + 86400, "wrong grace cutoff");
        vm.warp(start + _bound(elapsed, 0, 2 days));
        Attestation memory a = _attestation(1, 1);
        if (vm.getBlockTimestamp() <= start + 86400) {
            _pin(a);
        } else {
            _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        }
        a.runId = bytes32(uint256(2));
        a.score = 2;
        _submit(board, a, _sign(board, KEY_B, a));
        _assertBest(board, a);
    }

    function testGraceAcceptsAtCutoffAndRejectsOneSecondLater() public {
        _rotate(KEY_B);
        vm.warp(board.previousSignerValidUntil());
        _pin(_attestation(1, 1));
        vm.warp(vm.getBlockTimestamp() + 1);
        Attestation memory a = _attestation(2, 2);
        _reject(board, a, _sign(board, KEY_A, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
    }
}
