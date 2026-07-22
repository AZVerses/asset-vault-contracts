// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AssetVault} from "../src/AssetVault.sol";

/// @notice Grants roles from scripts/configs/roles.json.
///
/// Direct role config:
///   roles = vault role holders; existing grants are skipped.
///
/// Timelock role config:
///   roles = proposer candidates; the vault role is granted only to the
///   configured TimelockController. `timelockAddress` is required. The
///   executor defaults to the current script caller, and the canceller
///   defaults to the proposer, matching OpenZeppelin TimelockController v5.6.1.
///   Existing proposer, canceller, and executor members are reconciled from
///   RoleGranted/RoleRevoked logs, so stale members are revoked.
contract SetupAdminRoles is Script {
    string internal constant CONFIG_PATH = "/scripts/configs/roles.json";
    bytes32 internal constant ROLE_GRANTED_EVENT = keccak256("RoleGranted(bytes32,address,address)");
    bytes32 internal constant ROLE_REVOKED_EVENT = keccak256("RoleRevoked(bytes32,address,address)");

    struct RoleConfig {
        string roleName;
        bytes32 roleHash;
        address[] roles;
        bool skip;
        bool isTimelock;
        uint256 timelockDelay;
        address timelockProposer;
        address timelockCanceller;
        address timelockExecutor;
        address timelockAddress;
    }

    function run() external {
        uint256 privateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address caller = vm.addr(privateKey);
        AssetVault vault = _vault();
        string memory json = _readConfig();
        uint256 count = _arrayLength(json, ".", "roleName");

        vm.startBroadcast(privateKey);
        for (uint256 i = 0; i < count; ++i) {
            RoleConfig memory config = _readRole(json, i);
            if (config.skip) {
                console.log("Skipped role config:", config.roleName);
                continue;
            }
            _validateRoleConfig(config);
            _setupRole(vault, config, caller);
        }
        vm.stopBroadcast();
    }

    function _setupRole(AssetVault vault, RoleConfig memory config, address caller) internal {
        bytes32 role = _resolveRoleHash(config);
        _requireVaultRoleAdmin(vault, role, caller);

        if (!config.isTimelock) {
            for (uint256 i = 0; i < config.roles.length; ++i) {
                if (vault.hasRole(role, config.roles[i])) {
                    console.log("Role already granted:", config.roleName, config.roles[i]);
                    continue;
                }
                vault.grantRole(role, config.roles[i]);
                console.log("Granted role:", config.roleName, config.roles[i]);
            }
            return;
        }

        address proposer = config.timelockProposer == address(0) ? config.roles[0] : config.timelockProposer;
        address canceller = config.timelockCanceller == address(0) ? proposer : config.timelockCanceller;
        address executor = config.timelockExecutor == address(0) ? caller : config.timelockExecutor;
        address timelockAddress = config.timelockAddress;
        TimelockController timelock;
        if (timelockAddress == address(0)) {
            require(
                vm.envOr("DEPLOY_TIMELOCK", false),
                "timelockAddress is required (or set DEPLOY_TIMELOCK=true for first deployment)"
            );
            address[] memory proposers = new address[](1);
            proposers[0] = proposer;
            address[] memory executors = new address[](1);
            executors[0] = executor;
            timelock = new TimelockController(config.timelockDelay, proposers, executors, caller);
            timelockAddress = address(timelock);
            console.log("Deployed TimelockController; verify this address:", timelockAddress);
        } else {
            require(timelockAddress.code.length > 0, "timelockAddress has no code");
            timelock = TimelockController(payable(timelockAddress));
            require(timelock.getMinDelay() == config.timelockDelay, "timelock delay mismatch");
        }

        _syncTimelockRole(timelock, timelock.PROPOSER_ROLE(), proposer, caller);
        _syncTimelockRole(timelock, timelock.CANCELLER_ROLE(), canceller, caller);
        _syncTimelockRole(timelock, timelock.EXECUTOR_ROLE(), executor, caller);

        // TimelockController is self-administered by design. The constructor
        // grants the deployer a bootstrap DEFAULT_ADMIN_ROLE; remove it after
        // the configured sub-roles have been reconciled.
        if (timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), caller)) {
            timelock.renounceRole(timelock.DEFAULT_ADMIN_ROLE(), caller);
            console.log("Renounced bootstrap Timelock admin:", caller);
        }

        if (!vault.hasRole(role, timelockAddress)) {
            vault.grantRole(role, timelockAddress);
            console.log("Granted timelocked role:", config.roleName, timelockAddress);
        } else {
            console.log("Timelocked role already granted:", config.roleName, timelockAddress);
        }
    }

    function _syncTimelockRole(TimelockController timelock, bytes32 role, address expected, address caller) internal {
        address[] memory candidates = _timelockRoleCandidates(address(timelock), role);
        bool needsChange = !timelock.hasRole(role, expected);
        for (uint256 i = 0; i < candidates.length; ++i) {
            address candidate = candidates[i];
            if (candidate != expected && timelock.hasRole(role, candidate)) {
                needsChange = true;
            }
        }

        if (!needsChange) {
            console.log("Timelock role matches:", expected);
            return;
        }

        require(
            timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), caller),
            "caller cannot reconcile timelock roles"
        );
        for (uint256 i = 0; i < candidates.length; ++i) {
            address candidate = candidates[i];
            if (candidate != expected && timelock.hasRole(role, candidate)) {
                timelock.revokeRole(role, candidate);
                console.log("Revoked stale Timelock role member:", candidate);
            }
        }
        timelock.grantRole(role, expected);
        console.log("Granted Timelock role member:", expected);
    }

    function _timelockRoleCandidates(address timelock, bytes32 role)
        internal
        view
        returns (address[] memory members)
    {
        bytes32[] memory grantTopics = new bytes32[](1);
        grantTopics[0] = ROLE_GRANTED_EVENT;
        bytes32[] memory revokeTopics = new bytes32[](1);
        revokeTopics[0] = ROLE_REVOKED_EVENT;

        VmSafe.EthGetLogs[] memory grants = vm.eth_getLogs(0, block.number, timelock, grantTopics);
        VmSafe.EthGetLogs[] memory revokes = vm.eth_getLogs(0, block.number, timelock, revokeTopics);
        address[] memory candidates = new address[](grants.length + revokes.length);
        uint256 count;

        count = _collectTimelockRoleCandidates(grants, role, candidates, count);
        count = _collectTimelockRoleCandidates(revokes, role, candidates, count);

        members = new address[](count);
        for (uint256 i = 0; i < count; ++i) {
            members[i] = candidates[i];
        }
    }

    function _collectTimelockRoleCandidates(
        VmSafe.EthGetLogs[] memory logs,
        bytes32 role,
        address[] memory candidates,
        uint256 count
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics.length < 3 || logs[i].topics[1] != role) continue;
            address candidate = address(uint160(uint256(logs[i].topics[2])));
            bool seen;
            for (uint256 j = 0; j < count; ++j) {
                if (candidates[j] == candidate) {
                    seen = true;
                    break;
                }
            }
            if (!seen) candidates[count++] = candidate;
        }
        return count;
    }

    function _readRole(string memory json, uint256 index) internal view returns (RoleConfig memory config) {
        string memory base = string.concat(".[", vm.toString(index), "]");
        config.roleName = vm.parseJsonString(json, string.concat(base, ".roleName"));
        config.skip = _readBoolOr(json, string.concat(base, ".skip"), false);
        if (config.skip) return config;
        string memory hashPath = string.concat(base, ".roleHash");
        if (!vm.keyExistsJson(json, hashPath)) hashPath = string.concat(base, ".roleHashL");
        config.roleHash = vm.keyExistsJson(json, hashPath) ? vm.parseJsonBytes32(json, hashPath) : bytes32(0);
        config.roles = vm.parseJsonAddressArray(json, string.concat(base, ".roles"));
        config.isTimelock = vm.parseJsonBool(json, string.concat(base, ".isTimelock"));
        config.timelockDelay = _readUintOr(json, string.concat(base, ".timelockDelay"), 0);
        config.timelockProposer = _readAddressOr(json, string.concat(base, ".timelockProposer"), address(0));
        config.timelockCanceller = _readAddressOr(json, string.concat(base, ".timelockCanceller"), address(0));
        config.timelockExecutor = _readAddressOr(json, string.concat(base, ".timelockExecutor"), address(0));
        config.timelockAddress = _readAddressOr(json, string.concat(base, ".timelockAddress"), address(0));
    }

    function _validateRoleConfig(RoleConfig memory config) internal pure {
        require(bytes(config.roleName).length > 0, "roleName is empty");
        if (config.isTimelock) {
            require(config.timelockDelay > 0, "timelockDelay must be nonzero");
            require(config.roles.length > 0 || config.timelockProposer != address(0), "timelock proposer missing");
        }
    }

    function _resolveRoleHash(RoleConfig memory config) internal pure returns (bytes32 role) {
        role = keccak256(bytes(config.roleName));
        if (_equal(config.roleName, "DEFAULT_ADMIN_ROLE")) role = bytes32(0);
        if (config.roleHash != bytes32(0)) require(config.roleHash == role, "roleHash mismatch");
    }

    function _equal(string memory left, string memory right) internal pure returns (bool) {
        return keccak256(bytes(left)) == keccak256(bytes(right));
    }

    function _arrayLength(string memory json, string memory base, string memory field)
        internal
        view
        returns (uint256 length)
    {
        while (vm.keyExistsJson(json, string.concat(base, ".[", vm.toString(length), "].", field))) ++length;
    }

    function _readUintOr(string memory json, string memory path, uint256 defaultValue) internal view returns (uint256) {
        return vm.keyExistsJson(json, path) ? vm.parseJsonUint(json, path) : defaultValue;
    }

    function _readBoolOr(string memory json, string memory path, bool defaultValue) internal view returns (bool) {
        return vm.keyExistsJson(json, path) ? vm.parseJsonBool(json, path) : defaultValue;
    }

    function _readAddressOr(string memory json, string memory path, address defaultValue)
        internal
        view
        returns (address)
    {
        return vm.keyExistsJson(json, path) ? vm.parseJsonAddress(json, path) : defaultValue;
    }

    function _vault() internal view returns (AssetVault vault) {
        vault = AssetVault(payable(vm.envAddress("VAULT_ADDRESS")));
        require(address(vault).code.length > 0, "VAULT_ADDRESS has no code");
    }

    function _readConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), CONFIG_PATH));
    }

    function _requireVaultRoleAdmin(AssetVault vault, bytes32 role, address caller) internal view {
        require(vault.hasRole(vault.getRoleAdmin(role), caller), "caller cannot manage vault role");
    }
}
