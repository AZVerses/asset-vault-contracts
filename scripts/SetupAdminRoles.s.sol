// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AssetVault} from "../src/AssetVault.sol";

/// @notice Grants roles from scripts/configs/roles.json.
///
/// Direct role config:
///   roles = vault role holders; existing grants are skipped.
///
/// Timelock role config:
///   roles = proposer candidates; the vault role is granted only to the
///   TimelockController. `timelockAddress` is optional for first deployment;
///   write the emitted address back to JSON before rerunning the script.
///   The executor defaults to the current script caller, and the canceller
///   defaults to the proposer, matching OpenZeppelin TimelockController v5.6.1.
contract SetupAdminRoles is Script {
    string internal constant CONFIG_PATH = "/scripts/configs/roles.json";

    struct RoleConfig {
        string roleName;
        bytes32 roleHash;
        address[] roles;
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
            address[] memory proposers = new address[](1);
            proposers[0] = proposer;
            address[] memory executors = new address[](1);
            executors[0] = executor;
            timelock = new TimelockController(config.timelockDelay, proposers, executors, caller);
            timelockAddress = address(timelock);
            console.log("Deployed TimelockController for role:", config.roleName, timelockAddress);
        } else {
            require(timelockAddress.code.length > 0, "timelockAddress has no code");
            timelock = TimelockController(payable(timelockAddress));
            require(timelock.getMinDelay() == config.timelockDelay, "timelock delay mismatch");
        }

        _ensureTimelockRole(timelock, timelock.PROPOSER_ROLE(), proposer, caller);
        _ensureTimelockRole(timelock, timelock.CANCELLER_ROLE(), canceller, caller);
        _ensureTimelockRole(timelock, timelock.EXECUTOR_ROLE(), executor, caller);

        if (!vault.hasRole(role, timelockAddress)) {
            vault.grantRole(role, timelockAddress);
            console.log("Granted timelocked role:", config.roleName, timelockAddress);
        } else {
            console.log("Timelocked role already granted:", config.roleName, timelockAddress);
        }
    }

    function _ensureTimelockRole(TimelockController timelock, bytes32 role, address account, address caller) internal {
        if (timelock.hasRole(role, account)) return;
        require(timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), caller), "caller cannot manage timelock roles");
        timelock.grantRole(role, account);
    }

    function _readRole(string memory json, uint256 index) internal view returns (RoleConfig memory config) {
        string memory base = string.concat(".[", vm.toString(index), "]");
        config.roleName = vm.parseJsonString(json, string.concat(base, ".roleName"));
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

    function _readAddressOr(string memory json, string memory path, address defaultValue)
        internal
        view
        returns (address)
    {
        return vm.keyExistsJson(json, path) ? vm.parseJsonAddress(json, path) : defaultValue;
    }

    function _vault() internal returns (AssetVault vault) {
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
