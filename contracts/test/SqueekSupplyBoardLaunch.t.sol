// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "../../src/SqueekSupplyBoard.sol";

interface Vm {
    function chainId(uint256) external;
}

/// @dev Stands in for the launch factory: deploys the board with CREATE2 so the constructor runs with a
/// contract, not the test, as msg.sender.
contract FactoryProbe {
    function deploy(bytes memory code, bytes32 salt) external returns (address created) {
        assembly ("memory-safe") {
            created := create2(0, add(code, 32), mload(code), salt)
        }
        require(created != address(0), "constructor failed");
    }
}

/// @notice Rehearses what the evm_contracts launch needs: a nonpayable two-address constructor that runs
/// on an empty chain with the factory as msg.sender, an owner that is not the factory, a runtime within
/// EIP-170 and no DELEGATECALL, CALLCODE or SELFDESTRUCT reachable in the runtime.
contract SqueekSupplyBoardLaunchTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant OWNER = 0x51404e4A699e4E338e143fB2A45c5cdc96392575;
    address constant SIGNER = 0x2Dc8205A9650faFB65B51aE25cC34cEfDEe08653;

    function deployThroughFactory() internal returns (FactoryProbe factory, SqueekSupplyBoard board) {
        factory = new FactoryProbe();
        bytes memory code = abi.encodePacked(type(SqueekSupplyBoard).creationCode, abi.encode(OWNER, SIGNER));
        board = SqueekSupplyBoard(factory.deploy(code, keccak256("squeek")));
    }

    function testFactoryDeploymentDoesNotOwnTheBoard() public {
        vm.chainId(11155111);
        (FactoryProbe factory, SqueekSupplyBoard board) = deployThroughFactory();
        require(board.owner() == OWNER, "owner must be the constructor argument");
        require(board.owner() != address(factory), "factory must not own the board");
        require(board.owner() != address(this), "deployer must not own the board");
        require(board.pendingOwner() == address(0));
        require(board.signer() == SIGNER, "signer must be the constructor argument");
    }

    function testConstructorIsNonpayable() public {
        bytes memory code = abi.encodePacked(type(SqueekSupplyBoard).creationCode, abi.encode(OWNER, SIGNER));
        address created;
        assembly ("memory-safe") {
            created := create(1, add(code, 32), mload(code))
        }
        require(created == address(0), "payable deployment must fail");
    }

    function testRuntimeIsBoundedAndHasNoEscapeOpcodes() public {
        (, SqueekSupplyBoard board) = deployThroughFactory();
        bytes memory code = address(board).code;
        require(code.length > 0, "missing runtime");
        require(code.length <= 24_576, "runtime exceeds EIP-170");
        bool reachable = true;
        for (uint256 j; j < code.length; ++j) {
            uint8 op = uint8(code[j]);
            if (op == 0x5b) reachable = true;
            if (op >= 0x60 && op <= 0x7f) {
                j += op - 0x5f;
                continue;
            }
            if (reachable) require(op != 0xf4 && op != 0xf2 && op != 0xff, "forbidden application opcode");
            if (op == 0x00 || op == 0x56 || op == 0xf3 || op == 0xfd || op == 0xfe || op == 0xff) reachable = false;
        }
    }

    function testDomainSeparatorUsesSepoliaChainAndVersionTwo() public {
        vm.chainId(11155111);
        (, SqueekSupplyBoard board) = deployThroughFactory();
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            board.eip712Domain();
        require(keccak256(bytes(name)) == keccak256("SqueekSupply"));
        require(keccak256(bytes(version)) == keccak256("2"));
        require(chainId == 11155111);
        require(verifyingContract == address(board));
    }
}
