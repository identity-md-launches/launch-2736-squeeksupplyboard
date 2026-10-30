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
    event ChallengeConfigCleared(bytes32 indexed challengeId, bytes32 configHash, address lockedBy);

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

    // ---- Review finding 92af57a0: re-setting the active signer must not drop the replaced key ----

    function testSetSignerSameSignerRevertsAndKeepsGrace() public {
        uint64 deadline = 1000 + 86400;
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, deadline);
        board.setSigner(vm.addr(NEXT_KEY));
        vm.warp(1000 + 3600);
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.setSigner(vm.addr(NEXT_KEY));
        require(board.signer() == vm.addr(NEXT_KEY));
        require(board.previousSigner() == vm.addr(KEY));
        require(board.previousSignerValidUntil() == 1000 + board.SIGNER_GRACE_PERIOD());
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, deadline, sig);
        (uint64 score,) = board.best(CHALLENGE, player);
        require(score == 500);
    }

    function testSetSignerSameSignerRevertsWithoutPrevious() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.setSigner(vm.addr(KEY));
        require(board.previousSigner() == address(0));
    }

    function testSetSignerBackToPreviousIsARotation() public {
        board.setSigner(vm.addr(NEXT_KEY));
        vm.warp(1000 + 10);
        board.setSigner(vm.addr(KEY));
        require(board.signer() == vm.addr(KEY));
        require(board.previousSigner() == vm.addr(NEXT_KEY));
        require(board.previousSignerValidUntil() == 1010 + board.SIGNER_GRACE_PERIOD());
    }

    // ---- Review finding a479cf11: emergency rotation with no grace window in one transaction ----

    function testReplaceSignerRejectsReplacedKeyImmediately() public {
        uint64 deadline = 1000 + 86400;
        bytes memory sig = signature(bytes32(uint256(99)), CHALLENGE, CONFIG, player, 1_000_000, 1, deadline);
        vm.expectEmit(true, true, true, true);
        emit SignerChanged(vm.addr(KEY), vm.addr(NEXT_KEY));
        board.replaceSigner(vm.addr(NEXT_KEY));
        require(board.signer() == vm.addr(NEXT_KEY));
        require(board.previousSigner() == address(0));
        require(board.previousSignerValidUntil() == 0);
        vm.warp(1001);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(99)), CHALLENGE, CONFIG, 1_000_000, 1, deadline, sig);
        (uint64 score,) = board.best(CHALLENGE, player);
        require(score == 0);
        bytes memory fresh = signatureBy(NEXT_KEY, bytes32(uint256(2)), CHALLENGE, CONFIG, player, 500, 1, deadline);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 500, 1, deadline, fresh);
    }

    function testReplaceSignerAlsoRevokesUnexpiredPreviousSigner() public {
        address third = vm.addr(0x9ABC);
        board.setSigner(vm.addr(NEXT_KEY));
        vm.expectEmit(true, true, true, true);
        emit PreviousSignerRevoked(vm.addr(KEY));
        vm.expectEmit(true, true, true, true);
        emit SignerChanged(vm.addr(NEXT_KEY), third);
        board.replaceSigner(third);
        require(board.signer() == third);
        require(board.previousSigner() == address(0));
        require(board.previousSignerValidUntil() == 0);
        bytes memory oldest = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 500, 1, 2000, oldest);
        bytes memory replaced = signatureBy(NEXT_KEY, bytes32(uint256(2)), CHALLENGE, CONFIG, player, 500, 1, 2000);
        vm.expectRevert(SqueekSupplyBoard.BadSignature.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 500, 1, 2000, replaced);
    }

    function testReplaceSignerOwnerOnlyAndValidated() public {
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.replaceSigner(vm.addr(NEXT_KEY));
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.replaceSigner(address(0));
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.replaceSigner(vm.addr(KEY));
        require(board.signer() == vm.addr(KEY));
    }

    // ---- Review finding 4173811e: a lock written by a retired key can be cleared by the owner ----

    function testPinRecordsLockSigner() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        require(board.challengeConfig(CHALLENGE) == CONFIG);
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(KEY));
        // A later pin under the same lock does not re-attribute it.
        board.setSigner(vm.addr(NEXT_KEY));
        bytes memory next = signatureBy(NEXT_KEY, bytes32(uint256(2)), CHALLENGE, CONFIG, player, 124, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, CONFIG, 124, 2, 2000, next);
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(KEY));
    }

    function testLeakedPreviousSignerLockIsClearedAndHonestPinSucceeds() public {
        // Reviewer's sequence: A leaks, owner rotates to B, A pre-locks a future day inside its grace
        // window, owner revokes A, the day arrives and B's honest attestation must be recordable.
        vm.warp(1_800_000_000);
        bytes32 day = keccak256("squeek-supply:ss-2.0.0:2027-01-01");
        bytes32 junk = keccak256("junk");
        bytes32 real = keccak256("real rules+source");
        address attacker = address(0xBAD);
        board.setSigner(vm.addr(NEXT_KEY));
        uint64 deadline = uint64(block.timestamp + 86400);
        bytes memory evil = signature(keccak256("evil-run"), day, junk, attacker, 1, 1, deadline);
        vm.prank(attacker);
        board.pinScore(keccak256("evil-run"), day, junk, 1, 1, deadline, evil);
        require(board.challengeConfig(day) == junk);
        require(board.challengeConfigSigner(day) == vm.addr(KEY));
        board.revokePreviousSigner();
        vm.expectEmit(true, true, true, true);
        emit ChallengeConfigCleared(day, junk, vm.addr(KEY));
        board.clearChallengeConfig(day);
        require(board.challengeConfig(day) == bytes32(0));
        require(board.challengeConfigSigner(day) == address(0));
        // The attacker's own pin is history and stays recorded; the lock is what is cleared.
        (uint64 evilScore,) = board.best(day, attacker);
        require(evilScore == 1 && board.pinned(keccak256("evil-run")));
        vm.warp(1_830_000_000);
        deadline = uint64(block.timestamp + 86400);
        bytes memory honest = signatureBy(NEXT_KEY, keccak256("honest-run"), day, real, player, 500, 1, deadline);
        vm.prank(player);
        board.pinScore(keccak256("honest-run"), day, real, 500, 1, deadline, honest);
        require(board.challengeConfig(day) == real);
        require(board.challengeConfigSigner(day) == vm.addr(NEXT_KEY));
        (uint64 score, bytes32 run) = board.best(day, player);
        require(score == 500 && run == keccak256("honest-run"));
    }

    function testLeakedCurrentSignerLockIsClearableAfterReplaceSigner() public {
        bytes32 day = keccak256("future-day");
        bytes memory evil = signature(bytes32(uint256(7)), day, keccak256("junk"), player, 1, 1, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(7)), day, keccak256("junk"), 1, 1, 2000, evil);
        // Still the current signer: the lock is honoured.
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        board.clearChallengeConfig(day);
        board.replaceSigner(vm.addr(NEXT_KEY));
        board.clearChallengeConfig(day);
        require(board.challengeConfig(day) == bytes32(0));
    }

    function testClearChallengeConfigRefusedWhileLockingKeyInGrace() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        board.setSigner(vm.addr(NEXT_KEY));
        uint256 cutoff = board.previousSignerValidUntil();
        vm.warp(cutoff);
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        board.clearChallengeConfig(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == CONFIG);
        vm.warp(cutoff + 1);
        board.clearChallengeConfig(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == bytes32(0));
    }

    function testFuzzClearChallengeConfigOnlyAfterLockingKeyRetired(uint64 elapsed) public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        board.setSigner(vm.addr(NEXT_KEY));
        uint64 grace = board.SIGNER_GRACE_PERIOD();
        elapsed = elapsed % (3 * grace);
        vm.warp(1000 + elapsed);
        if (elapsed <= grace) vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        board.clearChallengeConfig(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == (elapsed <= grace ? CONFIG : bytes32(0)));
    }

    function testClearChallengeConfigOwnerOnly() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        board.replaceSigner(vm.addr(NEXT_KEY));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", player));
        vm.prank(player);
        board.clearChallengeConfig(CHALLENGE);
        require(board.challengeConfig(CHALLENGE) == CONFIG);
    }

    function testClearChallengeConfigNothingToClear() public {
        vm.expectRevert(SqueekSupplyBoard.InvalidConfiguration.selector);
        board.clearChallengeConfig(CHALLENGE);
    }

    function testClearedLockDoesNotReopenRunIdsOrLowerBest() public {
        bytes memory sig = signature(bytes32(uint256(1)), CHALLENGE, CONFIG, player, 123, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, CONFIG, 123, 2, 2000, sig);
        board.replaceSigner(vm.addr(NEXT_KEY));
        board.clearChallengeConfig(CHALLENGE);
        // The old runId stays spent even under the new signer and config.
        bytes memory replay =
            signatureBy(NEXT_KEY, bytes32(uint256(1)), CHALLENGE, keccak256("v2"), player, 200, 2, 2000);
        vm.expectRevert(SqueekSupplyBoard.AlreadyPinned.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(1)), CHALLENGE, keccak256("v2"), 200, 2, 2000, replay);
        // The player's best for the challenge still has to be exceeded.
        bytes memory lower =
            signatureBy(NEXT_KEY, bytes32(uint256(2)), CHALLENGE, keccak256("v2"), player, 100, 2, 2000);
        vm.expectRevert(SqueekSupplyBoard.NotHigher.selector);
        vm.prank(player);
        board.pinScore(bytes32(uint256(2)), CHALLENGE, keccak256("v2"), 100, 2, 2000, lower);
        bytes memory higher =
            signatureBy(NEXT_KEY, bytes32(uint256(3)), CHALLENGE, keccak256("v2"), player, 200, 2, 2000);
        vm.prank(player);
        board.pinScore(bytes32(uint256(3)), CHALLENGE, keccak256("v2"), 200, 2, 2000, higher);
        require(board.challengeConfig(CHALLENGE) == keccak256("v2"));
        require(board.challengeConfigSigner(CHALLENGE) == vm.addr(NEXT_KEY));
        // The new lock belongs to the active signer and is honoured again.
        vm.expectRevert(SqueekSupplyBoard.LockSignerActive.selector);
        board.clearChallengeConfig(CHALLENGE);
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
