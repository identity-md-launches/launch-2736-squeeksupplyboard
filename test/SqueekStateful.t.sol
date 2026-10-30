// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {SqueekSupplyBoard} from "src/SqueekSupplyBoard.sol";
import {ScoreHarness} from "./helpers/ScoreHarness.sol";
import {ScoreHandler} from "./helpers/ScoreHandler.sol";

/// forge-config: default.invariant.runs = 256
/// forge-config: default.invariant.depth = 64
/// forge-config: default.invariant.fail-on-revert = true
contract SqueekStatefulTest is ScoreHarness {
    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    ScoreHandler internal handler;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.chainId(11155111);
        SqueekSupplyBoard board = new SqueekSupplyBoard(WORKFLOW_OWNER, vm.addr(KEY_A));
        handler = new ScoreHandler(board);
        // Seed a consumed run so replay probes and historical invariants are meaningful from call one.
        // Other actors and challenges remain empty, allowing the fuzzer to explore first-pin locks.
        handler.submitImprovement(0, 0, 1, 0);
    }

    // These are Foundry's invariant target-discovery ABI, normally exposed by StdInvariant.
    // Implementing the small ABI locally avoids adding a vendored test library or changing remappings.
    function targetContracts() external view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function targetSelectors() external view returns (FuzzSelector[] memory targets) {
        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = ScoreHandler.submitImprovement.selector;
        selectors[1] = ScoreHandler.submitInvalid.selector;
        selectors[2] = ScoreHandler.replayAccepted.selector;
        selectors[3] = ScoreHandler.rotateSigner.selector;
        selectors[4] = ScoreHandler.usePreviousSigner.selector;
        selectors[5] = ScoreHandler.revokePrevious.selector;
        selectors[6] = ScoreHandler.advanceTime.selector;
        selectors[7] = ScoreHandler.nominateOwner.selector;
        selectors[8] = ScoreHandler.acceptOwner.selector;
        selectors[9] = ScoreHandler.unauthorizedAdministration.selector;
        targets = new FuzzSelector[](1);
        targets[0] = FuzzSelector(address(handler), selectors);
    }

    function invariant_BestsAndConfigurationsMatchAcceptedHistory() public view {
        handler.assertScoreHistory();
    }

    function invariant_OnlySuccessfullyAttestedRunsArePermanentlyConsumed() public view {
        handler.assertRunHistory();
    }

    function invariant_AdministrationRequiresTheModeledOwner() public view {
        handler.assertAdministration();
    }

    function afterInvariant() public view {
        require(handler.actions() > 1, "random handler actions were not executed");
    }

    function testHandlerExercisesSuccessfulAndRejectedTransitions() public {
        handler.submitImprovement(1, 1, 100, 5);
        for (uint256 failure; failure < 10; ++failure) {
            handler.submitInvalid(1, 1, failure);
        }
        handler.replayAccepted(0, 2, 2);
        handler.revokePrevious();
        handler.rotateSigner(0);
        handler.usePreviousSigner(0, 0);
        handler.advanceTime(86401);
        handler.usePreviousSigner(0, 0);
        handler.revokePrevious();
        handler.usePreviousSigner(0, 0);
        handler.nominateOwner(1);
        handler.acceptOwner(2);
        handler.acceptOwner(1);
        handler.rotateSigner(1);
        for (uint256 action; action < 4; ++action) {
            handler.unauthorizedAdministration(1, action);
        }
        handler.nominateOwner(2);
        handler.nominateOwner(4);
        handler.acceptOwner(2);
        handler.submitImprovement(3, 2, 10, 7);
        handler.assertScoreHistory();
        handler.assertRunHistory();
        handler.assertAdministration();
        require(handler.successfulPins() == 4, "successful paths not reached");
        require(handler.rejectedCalls() == 20, "rejection paths not reached");
        require(handler.rotations() == 2 && handler.timeAdvances() == 1, "admin and time paths not reached");
    }
}
