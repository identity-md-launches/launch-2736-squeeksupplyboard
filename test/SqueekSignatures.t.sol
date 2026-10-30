// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {BoardTestBase} from "./helpers/ScoreHarness.sol";

contract SqueekSignaturesTest is BoardTestBase {
    function testDomainAndTypeMatchBackendVersionTwo() public view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chain,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = board.eip712Domain();
        require(fields == hex"0f", "unexpected EIP-712 fields");
        require(keccak256(bytes(name)) == keccak256("SqueekSupply"), "domain name changed");
        require(keccak256(bytes(version)) == keccak256("2"), "domain version changed");
        require(chain == 11155111 && verifyingContract == address(board), "incorrect replay domain");
        require(salt == bytes32(0) && extensions.length == 0, "unexpected domain extension");
        require(board.SCORE_TYPEHASH() == SCORE_TYPEHASH, "attestation ABI changed");
    }

    function testEveryAttestationFieldIsAuthenticated() public {
        for (uint256 field; field < 7; ++field) {
            Attestation memory a = _attestation(10, 100);
            bytes memory signature = _sign(board, KEY_A, a);
            _mutate(a, field);
            _reject(board, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        }
        _pin(_attestation(10, 100));
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzMutationOfSignedFieldsFails(uint64 score, uint32 deliveries, uint8 field, bytes32 run) public {
        Attestation memory a = _attestation(1, uint64(_bound(score, 1, type(uint64).max - 1)));
        a.runId = run == bytes32(0) || run == bytes32(uint256(1)) ? bytes32(uint256(2)) : run;
        a.deliveries = deliveries;
        bytes memory signature = _sign(board, KEY_A, a);
        _mutate(a, field % 7);
        _reject(board, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
    }

    function _mutate(Attestation memory a, uint256 field) internal view {
        if (field == 0) a.runId ^= bytes32(uint256(1));
        if (field == 1) a.challengeId ^= bytes32(uint256(1));
        if (field == 2) a.configHash ^= bytes32(uint256(1));
        if (field == 3) a.player = otherPlayer;
        if (field == 4) a.score += 1;
        if (field == 5) a.deliveries ^= 1;
        if (field == 6) a.deadline += 1;
    }

    function testEveryDomainFieldIsAuthenticated() public {
        Attestation memory a = _attestation(1, 1);
        bytes32[4] memory wrongDomains = [
            _domain(address(board), vm.getChainId(), "SqueekSupplyStation", "2"),
            _domain(address(board), vm.getChainId(), "SqueekSupply", "1"),
            _domain(address(board), vm.getChainId() + 1, "SqueekSupply", "2"),
            _domain(address(this), vm.getChainId(), "SqueekSupply", "2")
        ];
        for (uint256 i; i < wrongDomains.length; ++i) {
            _reject(
                board,
                a,
                _signDigest(KEY_A, _digest(a, wrongDomains[i])),
                abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector)
            );
        }
        _pin(a);
    }

    function testSignatureCannotReplayOnAnotherBoardWithSameOwnerAndSigner() public {
        SqueekSupplyBoard second = new SqueekSupplyBoard(WORKFLOW_OWNER, vm.addr(KEY_A));
        Attestation memory a = _attestation(1, 10);
        bytes memory signature = _sign(board, KEY_A, a);
        _reject(second, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        _submit(board, a, signature);
        _assertBest(board, a);
        _submit(second, a, _sign(second, KEY_A, a));
        _assertBest(second, a);
    }

    function testChainIdChangeInvalidatesCachedDomainUntilOriginalChainReturns() public {
        Attestation memory a = _attestation(1, 10);
        bytes memory signature = _sign(board, KEY_A, a);
        vm.chainId(1);
        _reject(board, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        (,,, uint256 chain,,,) = board.eip712Domain();
        require(chain == 1, "domain did not follow chain ID");
        vm.chainId(11155111);
        _submit(board, a, signature);
        _assertBest(board, a);
    }

    function testSignatureForPersonalSignCannotAuthorizeTypedData() public {
        Attestation memory a = _attestation(1, 10);
        bytes32 typedDigest = _digest(a, _domain(address(board), vm.getChainId(), "SqueekSupply", "2"));
        bytes32 personalDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", typedDigest));
        _reject(
            board,
            a,
            _signDigest(KEY_A, personalDigest),
            abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector)
        );
    }

    function testUnauthorizedSignatureDoesNotBurnLegitimatePlayersRun() public {
        Attestation memory a = _attestation(1, 10);
        bytes memory signature = _sign(board, KEY_A, a);
        a.player = otherPlayer;
        _reject(board, a, signature, abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector));
        a.player = player;
        _submit(board, a, signature);
        _assertBest(board, a);
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzMalformedSignatureLengthHasNoSideEffects(uint16 rawLength) public {
        uint256 length = _bound(rawLength, 0, 512);
        if (length == 65) length = 66;
        Attestation memory a = _attestation(1, 10);
        _reject(board, a, new bytes(length), abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", length));
    }

    function testEmptyAndTruncatedAndExtendedSignaturesAreRejected() public {
        Attestation memory a = _attestation(1, 10);
        uint256[4] memory lengths = [uint256(0), 1, 64, 66];
        for (uint256 i; i < lengths.length; ++i) {
            _reject(
                board,
                a,
                new bytes(lengths[i]),
                abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", lengths[i])
            );
        }
        _pin(a);
    }

    /// forge-config: default.fuzz.runs = 1000
    function testFuzzInvalidRecoveryIdIsRejected(uint8 v) public {
        if (v == 27 || v == 28) v = 29;
        Attestation memory a = _attestation(1, 10);
        bytes memory signature = _sign(board, KEY_A, a);
        signature[64] = bytes1(v);
        _reject(board, a, signature, abi.encodeWithSignature("ECDSAInvalidSignature()"));
    }

    function testZeroRecoveryAndHighSMalleabilityAreRejected() public {
        Attestation memory a = _attestation(1, 10);
        _reject(
            board,
            a,
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)),
            abi.encodeWithSignature("ECDSAInvalidSignature()")
        );

        bytes32 digest = _digest(a, _domain(address(board), vm.getChainId(), "SqueekSupply", "2"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(KEY_A, digest);
        uint256 curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(curveOrder - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        // Demonstrate that the rejected bytes really are a malleated signature of the trusted signer.
        require(ecrecover(digest, flippedV, r, highS) == vm.addr(KEY_A), "invalid malleability fixture");
        _reject(
            board,
            a,
            abi.encodePacked(r, highS, flippedV),
            abi.encodeWithSignature("ECDSAInvalidSignatureS(bytes32)", highS)
        );
        _pin(a);
    }

    function testOwnerIsNotAutomaticallyAnAttestationSigner() public {
        // A separate local key controls this test board's owner but is not its score signer.
        SqueekSupplyBoard owned = new SqueekSupplyBoard(vm.addr(UNAUTHORIZED_KEY), vm.addr(KEY_A));
        Attestation memory a = _attestation(1, 10);
        _reject(
            owned, a, _sign(owned, UNAUTHORIZED_KEY, a), abi.encodeWithSelector(SqueekSupplyBoard.BadSignature.selector)
        );
    }
}
