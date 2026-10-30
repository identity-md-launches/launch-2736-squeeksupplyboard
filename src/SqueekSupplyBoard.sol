// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Records server-attested scores. This contract does NOT replay the game.
/// @dev No token transfers, deposits, fees, upgrades or reward promises.
contract SqueekSupplyBoard is EIP712, Ownable2Step {
    bytes32 public constant SCORE_TYPEHASH = keccak256(
        "ScoreAttestation(bytes32 runId,bytes32 challengeId,bytes32 configHash,address player,uint64 score,uint32 deliveries,uint64 deadline)"
    );
    /// @notice How long the signer replaced by `setSigner` keeps validating attestations.
    /// @dev Equals the 24-hour deadline the backend puts on every attestation, so a rotation never
    /// cuts off an attestation a player already holds (audit finding 9b6a6be7). The owner can end the
    /// window early with `revokePreviousSigner` when the old key is compromised.
    uint64 public constant SIGNER_GRACE_PERIOD = 86_400;

    struct Best {
        uint64 score;
        bytes32 runId;
    }

    mapping(bytes32 => mapping(address => Best)) public best;
    mapping(bytes32 => bool) public pinned;
    mapping(bytes32 => bytes32) public challengeConfig;
    /// @notice Signer whose attestation wrote `challengeConfig[challengeId]`. Lets the owner tell a lock
    /// written by a retired (leaked) key from one written by a key still in service.
    mapping(bytes32 => address) public challengeConfigSigner;
    address public signer;
    /// @notice Signer replaced by the latest `setSigner`; still accepted until `previousSignerValidUntil`.
    address public previousSigner;
    /// @notice Last timestamp (inclusive) at which `previousSigner` is still accepted.
    uint64 public previousSignerValidUntil;

    error Expired();
    error BadSignature();
    error AlreadyPinned();
    error NotHigher();
    error InvalidConfiguration();
    error RenounceDisabled();
    error LockSignerActive();

    event ScorePinned(
        address indexed player,
        bytes32 indexed challengeId,
        bytes32 indexed runId,
        bytes32 configHash,
        uint64 score,
        uint32 deliveries
    );
    event SignerChanged(address oldSigner, address newSigner);
    event PreviousSignerRevoked(address previousSigner);
    event ChallengeConfigCleared(bytes32 indexed challengeId, bytes32 configHash, address lockedBy);

    constructor(address initialOwner, address initialSigner) EIP712("SqueekSupply", "2") Ownable(initialOwner) {
        if (initialSigner == address(0)) revert InvalidConfiguration();
        signer = initialSigner;
    }

    /// @notice Planned rotation of the attestation signer. The replaced signer stays valid for
    /// `SIGNER_GRACE_PERIOD`; only the immediately previous key is honoured, so a second rotation inside
    /// the window drops the older key. Re-setting the active signer is rejected so that a repeated or
    /// retried call cannot overwrite the grace window of the key that was actually replaced.
    function setSigner(address newSigner) external onlyOwner {
        address oldSigner = signer;
        if (newSigner == address(0) || newSigner == oldSigner) revert InvalidConfiguration();
        previousSigner = oldSigner;
        previousSignerValidUntil = uint64(block.timestamp) + SIGNER_GRACE_PERIOD;
        signer = newSigner;
        emit SignerChanged(oldSigner, newSigner);
    }

    /// @notice Emergency rotation after a key compromise: installs `newSigner` and ends every other key's
    /// validity in the same transaction, so no attestation from the replaced key (or from an unexpired
    /// previous signer) is accepted from this block on.
    function replaceSigner(address newSigner) external onlyOwner {
        address oldSigner = signer;
        if (newSigner == address(0) || newSigner == oldSigner) revert InvalidConfiguration();
        address revoked = previousSigner;
        if (revoked != address(0)) {
            delete previousSigner;
            delete previousSignerValidUntil;
            emit PreviousSignerRevoked(revoked);
        }
        signer = newSigner;
        emit SignerChanged(oldSigner, newSigner);
    }

    /// @notice Ends the grace window of the replaced signer immediately (e.g. after a key compromise).
    function revokePreviousSigner() external onlyOwner {
        address revoked = previousSigner;
        if (revoked == address(0)) revert InvalidConfiguration();
        delete previousSigner;
        delete previousSignerValidUntil;
        emit PreviousSignerRevoked(revoked);
    }

    /// @notice Clears the configHash lock of `challengeId` when it was written by a key that is no longer
    /// in service (neither the current signer nor an unexpired previous signer). A leaked key can otherwise
    /// pre-lock predictable future challengeIds to a junk configHash with no remedy once it is revoked.
    /// Locks written by a key still in service cannot be cleared: the one-config-per-challenge rule stands
    /// for every attestation the board currently trusts. Pins already recorded are never changed.
    function clearChallengeConfig(bytes32 challengeId) external onlyOwner {
        bytes32 locked = challengeConfig[challengeId];
        if (locked == bytes32(0)) revert InvalidConfiguration();
        address lockedBy = challengeConfigSigner[challengeId];
        if (lockedBy == signer || _isPreviousSigner(lockedBy)) revert LockSignerActive();
        delete challengeConfig[challengeId];
        delete challengeConfigSigner[challengeId];
        emit ChallengeConfigCleared(challengeId, locked, lockedBy);
    }

    /// @notice Disabled: an ownerless board could never rotate its signer again (audit finding d7ebb0e8).
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    function pinScore(
        bytes32 runId,
        bytes32 challengeId,
        bytes32 configHash,
        uint64 score,
        uint32 deliveries,
        uint64 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert Expired();
        if (pinned[runId]) revert AlreadyPinned();
        if (runId == bytes32(0) || challengeId == bytes32(0) || configHash == bytes32(0)) {
            revert InvalidConfiguration();
        }
        if (score <= best[challengeId][msg.sender].score) revert NotHigher();
        bytes32 known = challengeConfig[challengeId];
        if (known != bytes32(0) && known != configHash) revert InvalidConfiguration();
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(SCORE_TYPEHASH, runId, challengeId, configHash, msg.sender, score, deliveries, deadline)
            )
        );
        address recovered = ECDSA.recover(digest, signature);
        if (recovered != signer && !_isPreviousSigner(recovered)) revert BadSignature();
        pinned[runId] = true;
        if (known == bytes32(0)) {
            challengeConfig[challengeId] = configHash;
            challengeConfigSigner[challengeId] = recovered;
        }
        best[challengeId][msg.sender] = Best(score, runId);
        emit ScorePinned(msg.sender, challengeId, runId, configHash, score, deliveries);
    }

    function _isPreviousSigner(address recovered) internal view returns (bool) {
        return recovered == previousSigner && block.timestamp <= previousSignerValidUntil;
    }
}
