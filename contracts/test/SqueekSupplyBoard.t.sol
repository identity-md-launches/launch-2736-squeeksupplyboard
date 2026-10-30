// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "../../src/SqueekSupplyBoard.sol";

interface Vm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function prank(address) external;
    function warp(uint256) external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function expectRevert() external;
    function expectEmit(bool, bool, bool, bool) external;
}

contract SqueekSupplyBoardTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SqueekSupplyBoard board;
    uint256 constant KEY = 0x1234;
    uint256 constant NEXT_KEY = 0x5678;
    address player = address(0xA11CE);
    bytes32 constant CHALLENGE = keccak256("daily");
    bytes32 constant CONFIG = keccak256("rules+source");

    event SignerChanged(address oldSigner, address newSigner);
    event PreviousSignerRevoked(address previousSigner);

    function setUp() public {
        board = new SqueekSupplyBoard(address(this), vm.addr(KEY));
        vm.warp(1000);
    }

    function signature(
        bytes32 run,
        bytes32 challenge,
        bytes32 config,
        address who,
        uint64 score,
        uint32 deliveries,
        uint64 deadline
    ) internal returns (bytes memory) {
        return signatureBy(KEY, run, challenge, config, who, score, deliveries, deadline);
    }

    function signatureBy(
        uint256 key,
        bytes32 run,
        bytes32 challenge,
        bytes32 config,
        address who,
        uint64 score,
        uint32 deliveries,
        uint64 deadline
    ) internal returns (bytes memory) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("SqueekSupply"),
                keccak256("2"),
                block.chainid,
                address(board)
            )
        );
        bytes32 body =
            keccak256(abi.encode(board.SCORE_TYPEHASH(), run, challenge, config, who, score, deliveries, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, keccak256(abi.encodePacked("\x19\x01", domain, body)));
        return abi.encodePacked(r, s, v);
    }

    function testValidPinAndReplay() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        (uint64 score, bytes32 run) = board.best(CHALLENGE, player);
        require(score == 123 && run == bytes32(uint256(1)));
        vm.expectRevert(SqueekSupplyBoard.AlreadyPinned.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
    }

    function testExpired() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 999);
        vm.expectRevert(SqueekSupplyBoard.Expired.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 999, sig);
    }

    function testDifferentPlayer() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
    }

    function testTamperedConfig() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, keccak256("fake"), 123, 2, 2000, sig);
    }

    function testNotHigher() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        vm.expectRevert(SqueekSupplyBoard.NotHigher.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
    }

    function testSignerOwnerOnly() public {
        vm.expectRevert();
        vm.prank(player);
        board.setSigner(player);
        board.setSigner(player);
        require(board.signer() == player);
    }

    function testConfigFrozen() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, keccak256("different"), 124, 2, 2000, sig);
    }

    function testFuzzScore(uint64 value) public {
        if (value == 0) return;
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, value, 0, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, value, 0, 2000, sig);
        (uint64 stored,) = board.best(CHALLENGE, player);
        require(stored == value);
    }

    // ---- Constructor ----

    function testConstructorRejectsZeroSigner() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        new SqueekSupplyBoard(address(this), address(0));
    }

    function testConstructorRejectsZeroOwner() public {
        vm.expectRevert(abi.encodeWithSignature("OwnableInvalidOwner(address)", address(0)));
        new SqueekSupplyBoard(address(0), vm.addr(KEY));
    }

    function testConstructorSetsOwnerAndSignerWithoutGrace() public {
        require(board.owner() == address(this));
        require(board.signer() == vm.addr(KEY));
        require(board.previousSigner() == address(0));
        require(board.previousSignerValidUntil() == 0);
    }

    // ---- Audit finding 9b6a6be7: rotation must not invalidate unexpired attestations ----

    function testRotationKeepsUnexpiredAttestationValid() public {
        uint64 deadline = 1000 + 86400;
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, deadline);
        vm.expectEmit(true, true, true, true);
        emit SignerChanged(vm.addr(KEY), vm.addr(NEXT_KEY));
        board.setSigner(vm.addr(NEXT_KEY));
        require(board.signer() == vm.addr(NEXT_KEY));
        require(board.previousSigner() == vm.addr(KEY));
        require(board.previousSignerValidUntil() == 1000 + board.SIGNER_GRACE_PERIOD());
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, deadline, sig);
        (uint64 score, bytes32 run) = board.best(CHALLENGE, player);
        require(score == 500 && run == bytes32(uint256(1)));
    }

    function testRotationAcceptsNewSignerImmediately() public {
        board.setSigner(vm.addr(NEXT_KEY));
        bytes memory sig = signatureBy(NEXT_KEY, bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, 2000, sig);
        (uint64 score,) = board.best(CHALLENGE, player);
        require(score == 500);
    }

    function testPreviousSignerRejectedAfterGrace() public {
        board.setSigner(vm.addr(NEXT_KEY));
        uint256 cutoff = board.previousSignerValidUntil();
        uint64 deadline = uint64(cutoff + 1000);
        // Accepted at the last second of the window.
        vm.warp(cutoff);
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, deadline);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, deadline, sig);
        // Rejected one second later even though the attestation's own deadline has not passed.
        vm.warp(cutoff + 1);
        bytes memory late = signature(bytes32(uint256(2)), CHALLENGE, CONFIG, player, 600, 1, deadline);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 600, 1, deadline, late);
    }

    function testFuzzPreviousSignerWindow(uint64 elapsed) public {
        board.setSigner(vm.addr(NEXT_KEY));
        uint64 grace = board.SIGNER_GRACE_PERIOD();
        elapsed = elapsed % (3 * grace);
        vm.warp(1000 + elapsed);
        uint64 deadline = type(uint64).max;
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, deadline);
        if (elapsed > grace) vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, deadline, sig);
        (uint64 score,) = board.best(CHALLENGE, player);
        require(score == (elapsed > grace ? 0 : 500));
    }

    function testSecondRotationDropsOlderSigner() public {
        address third = vm.addr(0x9ABC);
        board.setSigner(vm.addr(NEXT_KEY));
        board.setSigner(third);
        require(board.signer() == third);
        require(board.previousSigner() == vm.addr(NEXT_KEY));
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, 2000, sig);
    }

    function testRevokePreviousSignerCutsWindow() public {
        board.setSigner(vm.addr(NEXT_KEY));
        vm.expectEmit(true, true, true, true);
        emit PreviousSignerRevoked(vm.addr(KEY));
        board.revokePreviousSigner();
        require(board.previousSigner() == address(0));
        require(board.previousSignerValidUntil() == 0);
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, 2000, sig);
        // The current signer is unaffected.
        bytes memory fresh = signatureBy(NEXT_KEY, bytes32(uint256(2)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 500, 1, 2000, fresh);
    }

    function testRevokePreviousSignerOwnerOnly() public {
        board.setSigner(vm.addr(NEXT_KEY));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.revokePreviousSigner();
        require(board.previousSigner() == vm.addr(KEY));
    }

    function testRevokePreviousSignerNothingToRevoke() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.revokePreviousSigner();
    }

    // ---- Audit finding d7ebb0e8: ownership cannot be renounced ----

    function testRenounceOwnershipDisabled() public {
        vm.expectRevert(SqueekSupplyBoard.RenounceDisabled.selector);
        board.renounceOwnership();
        require(board.owner() == address(this));
        board.setSigner(vm.addr(NEXT_KEY));
        require(board.signer() == vm.addr(NEXT_KEY));
    }

    function testRenounceOwnershipDisabledForEveryone() public {
        vm.expectRevert(SqueekSupplyBoard.RenounceDisabled.selector);
        vm.prank(player);
        board.renounceOwnership();
    }

    function testTwoStepOwnershipTransferStillWorks() public {
        address next = address(0xB0B);
        board.transferOwnership(next);
        require(board.owner() == address(this) && board.pendingOwner() == next);
        vm.prank(next);
        board.acceptOwnership();
        require(board.owner() == next);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(this)));
        board.setSigner(player);
        vm.prank(next);
        board.setSigner(player);
        require(board.signer() == player);
    }
}
