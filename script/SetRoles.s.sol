// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AssetVault} from "../src/AssetVault.sol";

// Usage:
// 1. Update `ops/config/set-roles.json` with the target Safe addresses and any existing timelock address.
// 2. Dry run:
//    forge script script/SetRoles.s.sol:SetRoles --rpc-url <RPC_URL>
// 3. Broadcast:
//    AZ_DEPLOYER_PRIVATE_KEY=<pk> forge script script/SetRoles.s.sol:SetRoles --rpc-url <RPC_URL> --broadcast
// 4. Force repair for explicitly configured legacy holders:
//    FORCE_SET=true AZ_DEPLOYER_PRIVATE_KEY=<pk> forge script script/SetRoles.s.sol:SetRoles --rpc-url <RPC_URL> --broadcast
// 5. Optional config override:
//    SET_ROLES_CONFIG_PATH=/abs/path/to/set-roles.json forge script ...
//
// Notes:
// - `ADMIN_ROLE` and `UPGRADE_ROLE` are expected to be timelock-backed.
// - Existing timelock delay mismatches are treated as blockers, because OZ timelock delay can only be updated
//   by the timelock itself through a scheduled self-call.
contract SetRoles is Script {
    using stdJson for string;

    string internal constant HOLDER_TYPE_DIRECT_SAFE = "DIRECT_SAFE";
    string internal constant HOLDER_TYPE_TIMELOCK = "TIMELOCK";

    struct ChainConfig {
        string key;
        uint256 chainId;
        address vault;
        string[] roleOrder;
    }

    struct RoleConfig {
        string key;
        string name;
        string holderType;
        address safe;
        address timelock;
        uint256 minDelay;
        address[] revokeFrom;
    }

    error MissingChainConfig(uint256 chainId);
    error MissingConfigFile(string path);
    error InvalidHolderType(string roleKey, string holderType);
    error InvalidDirectSafeConfig(string roleKey);
    error PreflightFailed(uint256 issueCount);
    error MissingVaultAdmin(bytes32 adminRole, address broadcaster);
    error MissingTimelockAdmin(address timelock, address broadcaster);

    function run() external {
        bool forceSet = vm.envOr("FORCE_SET", false);
        _run(forceSet);
    }

    function _run(bool forceSet) internal {
        uint256 privateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address broadcaster = vm.addr(privateKey);

        ChainConfig memory chainConfig = _loadChainConfig(block.chainid);
        AssetVault vault = AssetVault(payable(chainConfig.vault));

        if (address(vault).code.length == 0) {
            revert InvalidDirectSafeConfig("vault");
        }

        console.log("SetRoles preflight");
        console.log("Chain ID:", block.chainid);
        console.log("Broadcaster:", broadcaster);
        console.log("Vault:", address(vault));
        console.log("Force set:", forceSet);

        uint256 issues = _preflight(vault, chainConfig, broadcaster, forceSet);
        if (issues != 0) {
            revert PreflightFailed(issues);
        }

        console.log("Preflight passed. Applying role configuration...");

        vm.startBroadcast(privateKey);

        for (uint256 i = 0; i < chainConfig.roleOrder.length; ++i) {
            RoleConfig memory roleConfig = _loadRoleConfig(chainConfig.key, chainConfig.roleOrder[i]);
            bytes32 role = _roleHash(roleConfig.name);

            if (_isHolderType(roleConfig.holderType, HOLDER_TYPE_DIRECT_SAFE)) {
                _applyDirectRole(vault, roleConfig, role, broadcaster, forceSet);
                continue;
            }

            if (_isHolderType(roleConfig.holderType, HOLDER_TYPE_TIMELOCK)) {
                _applyTimelockRole(vault, roleConfig, role, broadcaster, forceSet);
                continue;
            }

            revert InvalidHolderType(roleConfig.key, roleConfig.holderType);
        }

        vm.stopBroadcast();
        console.log("SetRoles completed.");
    }

    function _preflight(
        AssetVault vault,
        ChainConfig memory chainConfig,
        address broadcaster,
        bool forceSet
    ) internal view returns (uint256 issues) {
        for (uint256 i = 0; i < chainConfig.roleOrder.length; ++i) {
            RoleConfig memory roleConfig = _loadRoleConfig(chainConfig.key, chainConfig.roleOrder[i]);
            bytes32 role = _roleHash(roleConfig.name);

            console.log("");
            console.log("Checking role:", roleConfig.name);

            if (_isHolderType(roleConfig.holderType, HOLDER_TYPE_DIRECT_SAFE)) {
                issues += _preflightDirectRole(vault, roleConfig, role, broadcaster, forceSet);
                continue;
            }

            if (_isHolderType(roleConfig.holderType, HOLDER_TYPE_TIMELOCK)) {
                issues += _preflightTimelockRole(vault, roleConfig, role, broadcaster, forceSet);
                continue;
            }

            console.log("BLOCKER: unsupported holderType");
            issues += 1;
        }
    }

    function _preflightDirectRole(
        AssetVault vault,
        RoleConfig memory roleConfig,
        bytes32 role,
        address broadcaster,
        bool forceSet
    ) internal view returns (uint256 issues) {
        if (roleConfig.safe == address(0)) {
            console.log("BLOCKER: direct safe is zero address");
            return 1;
        }

        bool expectedHolderHasRole = vault.hasRole(role, roleConfig.safe);
        console.log("Expected direct holder:", roleConfig.safe);
        console.log("Expected holder already set:", expectedHolderHasRole);

        bytes32 adminRole = vault.getRoleAdmin(role);
        bool broadcasterCanManageRole = vault.hasRole(adminRole, broadcaster);

        if (!expectedHolderHasRole && !broadcasterCanManageRole) {
            console.log("BLOCKER: broadcaster cannot grant missing vault role");
            return 1;
        }

        for (uint256 i = 0; i < roleConfig.revokeFrom.length; ++i) {
            address staleHolder = roleConfig.revokeFrom[i];
            if (!vault.hasRole(role, staleHolder)) {
                continue;
            }

            console.log("Legacy holder still has role:", staleHolder);

            if (!forceSet) {
                console.log("BLOCKER: FORCE_SET=false, will not revoke legacy holder");
                issues += 1;
                continue;
            }

            if (!broadcasterCanManageRole) {
                console.log("BLOCKER: broadcaster cannot revoke legacy vault role");
                issues += 1;
                continue;
            }

            console.log("Will revoke legacy holder during execution.");
        }
    }

    function _preflightTimelockRole(
        AssetVault vault,
        RoleConfig memory roleConfig,
        bytes32 role,
        address broadcaster,
        bool forceSet
    ) internal view returns (uint256 issues) {
        if (roleConfig.safe == address(0) || roleConfig.minDelay == 0) {
            console.log("BLOCKER: timelock role requires non-zero safe and minDelay");
            return 1;
        }

        bytes32 vaultAdminRole = vault.getRoleAdmin(role);
        bool broadcasterCanManageVaultRole = vault.hasRole(vaultAdminRole, broadcaster);

        address timelockAddress = roleConfig.timelock;
        bool isNewDeployment = timelockAddress == address(0);

        if (isNewDeployment) {
            console.log("Timelock: will deploy new TimelockController");
            if (!broadcasterCanManageVaultRole) {
                console.log("BLOCKER: broadcaster cannot grant vault role to the new timelock");
                return 1;
            }
        } else {
            if (timelockAddress.code.length == 0) {
                console.log("BLOCKER: configured timelock has no code");
                return 1;
            }

            TimelockController timelock = TimelockController(payable(timelockAddress));
            console.log("Expected timelock holder:", timelockAddress);

            uint256 actualDelay = timelock.getMinDelay();
            console.log("Expected delay:", roleConfig.minDelay);
            console.log("Actual delay:", actualDelay);
            if (actualDelay != roleConfig.minDelay) {
                console.log("BLOCKER: existing timelock delay mismatch, cannot fix directly");
                issues += 1;
            }

            bool broadcasterCanManageTimelock = timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), broadcaster);
            issues += _preflightTimelockSubRole(
                timelock,
                timelock.PROPOSER_ROLE(),
                roleConfig.safe,
                broadcasterCanManageTimelock
            );
            issues += _preflightTimelockSubRole(
                timelock,
                timelock.EXECUTOR_ROLE(),
                roleConfig.safe,
                broadcasterCanManageTimelock
            );
            issues += _preflightTimelockSubRole(
                timelock,
                timelock.CANCELLER_ROLE(),
                roleConfig.safe,
                broadcasterCanManageTimelock
            );
        }

        bool expectedTimelockHasVaultRole = !isNewDeployment && vault.hasRole(role, timelockAddress);
        console.log("Timelock already has vault role:", expectedTimelockHasVaultRole);
        if (!expectedTimelockHasVaultRole && !broadcasterCanManageVaultRole) {
            console.log("BLOCKER: broadcaster cannot grant vault role to timelock");
            issues += 1;
        }

        for (uint256 i = 0; i < roleConfig.revokeFrom.length; ++i) {
            address staleHolder = roleConfig.revokeFrom[i];
            if (!vault.hasRole(role, staleHolder)) {
                continue;
            }

            console.log("Legacy holder still has role:", staleHolder);

            if (!forceSet) {
                console.log("BLOCKER: FORCE_SET=false, will not revoke legacy holder");
                issues += 1;
                continue;
            }

            if (!broadcasterCanManageVaultRole) {
                console.log("BLOCKER: broadcaster cannot revoke legacy vault role");
                issues += 1;
                continue;
            }

            console.log("Will revoke legacy holder during execution.");
        }
    }

    function _preflightTimelockSubRole(
        TimelockController timelock,
        bytes32 role,
        address expectedSafe,
        bool broadcasterCanManageTimelock
    ) internal view returns (uint256 issues) {
        bool hasRole = timelock.hasRole(role, expectedSafe);
        console.log("Timelock sub-role set:", hasRole);
        if (!hasRole && !broadcasterCanManageTimelock) {
            console.log("BLOCKER: existing timelock is missing sub-role and broadcaster is not timelock admin");
            return 1;
        }
    }

    function _applyDirectRole(
        AssetVault vault,
        RoleConfig memory roleConfig,
        bytes32 role,
        address broadcaster,
        bool forceSet
    ) internal {
        bytes32 adminRole = vault.getRoleAdmin(role);
        bool broadcasterCanManageRole = vault.hasRole(adminRole, broadcaster);
        if (!vault.hasRole(role, roleConfig.safe)) {
            if (!broadcasterCanManageRole) {
                revert MissingVaultAdmin(adminRole, broadcaster);
            }
            console.log("Granting direct role to:", roleConfig.safe);
            vault.grantRole(role, roleConfig.safe);
        }

        if (!forceSet) {
            return;
        }

        for (uint256 i = 0; i < roleConfig.revokeFrom.length; ++i) {
            address staleHolder = roleConfig.revokeFrom[i];
            if (!vault.hasRole(role, staleHolder)) {
                continue;
            }
            if (!broadcasterCanManageRole) {
                revert MissingVaultAdmin(adminRole, broadcaster);
            }
            console.log("Revoking direct role from legacy holder:", staleHolder);
            vault.revokeRole(role, staleHolder);
        }
    }

    function _applyTimelockRole(
        AssetVault vault,
        RoleConfig memory roleConfig,
        bytes32 role,
        address broadcaster,
        bool forceSet
    ) internal {
        bytes32 vaultAdminRole = vault.getRoleAdmin(role);
        bool broadcasterCanManageVaultRole = vault.hasRole(vaultAdminRole, broadcaster);
        address timelockAddress = roleConfig.timelock;
        bool isNewDeployment = timelockAddress == address(0);

        TimelockController timelock;
        if (isNewDeployment) {
            address[] memory proposers = new address[](1);
            proposers[0] = roleConfig.safe;

            address[] memory executors = new address[](1);
            executors[0] = roleConfig.safe;

            console.log("Deploying TimelockController for role:", roleConfig.name);
            timelock = new TimelockController(roleConfig.minDelay, proposers, executors, broadcaster);
            timelockAddress = address(timelock);
            console.log("New timelock deployed at:", timelockAddress);
        } else {
            timelock = TimelockController(payable(timelockAddress));
        }

        _ensureTimelockSubRole(
            timelock,
            timelock.PROPOSER_ROLE(),
            roleConfig.safe,
            broadcaster
        );
        _ensureTimelockSubRole(
            timelock,
            timelock.EXECUTOR_ROLE(),
            roleConfig.safe,
            broadcaster
        );
        _ensureTimelockSubRole(
            timelock,
            timelock.CANCELLER_ROLE(),
            roleConfig.safe,
            broadcaster
        );

        if (!vault.hasRole(role, timelockAddress)) {
            if (!broadcasterCanManageVaultRole) {
                revert MissingVaultAdmin(vaultAdminRole, broadcaster);
            }
            console.log("Granting vault role to timelock:", timelockAddress);
            vault.grantRole(role, timelockAddress);
        }

        if (forceSet) {
            for (uint256 i = 0; i < roleConfig.revokeFrom.length; ++i) {
                address staleHolder = roleConfig.revokeFrom[i];
                if (!vault.hasRole(role, staleHolder)) {
                    continue;
                }
                if (!broadcasterCanManageVaultRole) {
                    revert MissingVaultAdmin(vaultAdminRole, broadcaster);
                }
                console.log("Revoking vault role from legacy holder:", staleHolder);
                vault.revokeRole(role, staleHolder);
            }
        }

        if (isNewDeployment && timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), broadcaster)) {
            console.log("Renouncing bootstrap timelock admin from broadcaster");
            timelock.renounceRole(timelock.DEFAULT_ADMIN_ROLE(), broadcaster);
        }
    }

    function _ensureTimelockSubRole(
        TimelockController timelock,
        bytes32 role,
        address holder,
        address broadcaster
    ) internal {
        if (timelock.hasRole(role, holder)) {
            return;
        }

        if (!timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), broadcaster)) {
            revert MissingTimelockAdmin(address(timelock), broadcaster);
        }

        console.log("Granting timelock sub-role to:", holder);
        timelock.grantRole(role, holder);
    }

    function _loadChainConfig(uint256 chainId) internal view returns (ChainConfig memory chainConfig) {
        string memory json = _readConfigJson();
        string[] memory chainKeys = vm.parseJsonKeys(json, ".chains");

        for (uint256 i = 0; i < chainKeys.length; ++i) {
            string memory key = chainKeys[i];
            string memory basePath = string.concat(".chains.", key);

            if (json.readUint(string.concat(basePath, ".chainId")) != chainId) {
                continue;
            }

            chainConfig.key = key;
            chainConfig.chainId = chainId;
            chainConfig.vault = json.readAddress(string.concat(basePath, ".vault"));
            chainConfig.roleOrder = json.readStringArray(string.concat(basePath, ".roleOrder"));
            return chainConfig;
        }

        revert MissingChainConfig(chainId);
    }

    function _loadRoleConfig(
        string memory chainKey,
        string memory roleKey
    ) internal view returns (RoleConfig memory roleConfig) {
        string memory json = _readConfigJson();
        string memory basePath = string.concat(".chains.", chainKey, ".roles.", roleKey);

        roleConfig.key = roleKey;
        roleConfig.name = json.readString(string.concat(basePath, ".name"));
        roleConfig.holderType = json.readString(string.concat(basePath, ".holderType"));
        roleConfig.safe = json.readAddress(string.concat(basePath, ".safe"));
        roleConfig.timelock = json.readAddressOr(string.concat(basePath, ".timelock"), address(0));
        roleConfig.minDelay = json.readUintOr(string.concat(basePath, ".minDelay"), 0);
        roleConfig.revokeFrom = json.readAddressArrayOr(
            string.concat(basePath, ".revokeFrom"),
            new address[](0)
        );
    }

    function _roleHash(string memory roleName) internal pure returns (bytes32) {
        if (_stringEq(roleName, "DEFAULT_ADMIN_ROLE")) {
            return bytes32(0);
        }
        return keccak256(bytes(roleName));
    }

    function _isHolderType(string memory actual, string memory expected) internal pure returns (bool) {
        return keccak256(bytes(actual)) == keccak256(bytes(expected));
    }

    function _stringEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _readConfigJson() internal view returns (string memory) {
        string memory path = vm.envOr(
            "SET_ROLES_CONFIG_PATH",
            string.concat(vm.projectRoot(), "/ops/config/set-roles.json")
        );

        if (!vm.exists(path)) {
            revert MissingConfigFile(path);
        }

        return vm.readFile(path);
    }
}
