// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";

/// @dev Only Foundry's built-in cheatcodes are needed; no downloaded test dependencies.
interface ScoreVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function chainId(uint256 chainId) external;
    function deal(address account, uint256 balance) external;
    function getBlockTimestamp() external view returns (uint256);
    function getChainId() external view returns (uint256);
    function expectRevert(bytes calldata reason) external;
    function expectRevert(bytes4 selector) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

abstract contract ScoreHarness {
    ScoreVm internal constant vm = ScoreVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // Public, deterministic test fixtures, never deployment credentials.
    uint256 internal constant KEY_A = uint256(keccak256("score test signer A"));
    uint256 internal constant KEY_B = uint256(keccak256("score test signer B"));
    uint256 internal constant KEY_C = uint256(keccak256("score test signer C"));
    uint256 internal constant UNAUTHORIZED_KEY = uint256(keccak256("unauthorized test signer"));
    address internal constant WORKFLOW_OWNER = 0x51404e4A699e4E338e143fB2A45c5cdc96392575;
    address internal constant WORKFLOW_SIGNER = 0x2Dc8205A9650faFB65B51aE25cC34cEfDEe08653;
    bytes32 internal constant CHALLENGE = keccak256("test daily challenge");
    bytes32 internal constant CONFIG = keccak256("test ss-2.0.0 configuration");
    // Independently specified from the backend ABI, never read from the board to generate signatures.
    bytes32 internal constant SCORE_TYPEHASH = keccak256(
        "ScoreAttestation(bytes32 runId,bytes32 challengeId,bytes32 configHash,address player,uint64 score,uint32 deliveries,uint64 deadline)"
    );
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    struct Attestation {
        bytes32 runId;
        bytes32 challengeId;
        bytes32 configHash;
        address player;
        uint64 score;
        uint32 deliveries;
        uint64 deadline;
    }

    function _domain(address verifyingContract, uint256 chain, string memory name, string memory version)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chain, verifyingContract)
        );
    }

    function _digest(Attestation memory a, bytes32 domain) internal pure returns (bytes32) {
        bytes32 body = keccak256(
            abi.encode(
                SCORE_TYPEHASH, a.runId, a.challengeId, a.configHash, a.player, a.score, a.deliveries, a.deadline
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, body));
    }

    function _signDigest(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sign(SqueekSupplyBoard target, uint256 key, Attestation memory a) internal returns (bytes memory) {
        return _signDigest(key, _digest(a, _domain(address(target), vm.getChainId(), "SqueekSupply", "2")));
    }

    function _submit(SqueekSupplyBoard target, Attestation memory a, bytes memory signature) internal {
        vm.prank(a.player);
        target.pinScore(a.runId, a.challengeId, a.configHash, a.score, a.deliveries, a.deadline, signature);
    }

    function _calldata(Attestation memory a, bytes memory signature) internal pure returns (bytes memory) {
        return abi.encodeCall(
            SqueekSupplyBoard.pinScore,
            (a.runId, a.challengeId, a.configHash, a.score, a.deliveries, a.deadline, signature)
        );
    }

    /// @dev Keeps already-in-range values, including exact boundaries; never discards a fuzz run.
    function _bound(uint256 value, uint256 minimum, uint256 maximum) internal pure returns (uint256) {
        require(minimum <= maximum, "invalid test bounds");
        if (value >= minimum && value <= maximum) return value;
        return minimum + value % (maximum - minimum + 1);
    }

    function _assertBest(SqueekSupplyBoard target, Attestation memory a) internal view {
        (uint64 score, bytes32 run) = target.best(a.challengeId, a.player);
        require(score == a.score, "best score differs from attested score");
        require(run == a.runId, "best run differs from attested run");
        require(target.pinned(a.runId), "successful run was not consumed");
        require(target.challengeConfig(a.challengeId) == a.configHash, "configuration not locked");
    }

    function _scoreState(SqueekSupplyBoard target, Attestation memory a) internal view returns (bytes32) {
        (uint64 score, bytes32 run) = target.best(a.challengeId, a.player);
        return keccak256(abi.encode(score, run, target.pinned(a.runId), target.challengeConfig(a.challengeId)));
    }

    /// @dev Exact revert data plus before/after state checks prevent a negative test passing for the wrong reason.
    function _reject(SqueekSupplyBoard target, Attestation memory a, bytes memory signature, bytes memory reason)
        internal
    {
        bytes32 beforeState = _scoreState(target, a);
        vm.expectRevert(reason);
        _submit(target, a, signature);
        require(_scoreState(target, a) == beforeState, "rejected pin changed score state");
    }
}

abstract contract BoardTestBase is ScoreHarness {
    SqueekSupplyBoard internal board;
    address internal player;
    address internal otherPlayer;

    function setUp() public virtual {
        vm.warp(1_800_000_000);
        vm.chainId(11155111);
        player = vm.addr(uint256(keccak256("score test player")));
        otherPlayer = vm.addr(uint256(keccak256("other score test player")));
        board = new SqueekSupplyBoard(WORKFLOW_OWNER, vm.addr(KEY_A));
    }

    function _attestation(uint256 run, uint64 score) internal view returns (Attestation memory) {
        return Attestation(bytes32(run), CHALLENGE, CONFIG, player, score, 3, uint64(vm.getBlockTimestamp() + 1 days));
    }

    function _pin(Attestation memory a) internal {
        _submit(board, a, _sign(board, KEY_A, a));
        _assertBest(board, a);
    }

    function _rotate(uint256 key) internal {
        address next = vm.addr(key);
        vm.prank(WORKFLOW_OWNER);
        board.setSigner(next);
    }
}
