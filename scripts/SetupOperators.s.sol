// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {AssetVault} from "../src/AssetVault.sol";

/// @notice Grants OPERATOR_ROLE to every address in scripts/configs/operators.json.
/// Existing grants are skipped.
contract SetupOperators is Script {
    string internal constant CONFIG_PATH = "/scripts/configs/operators.json";

    function run() external {
        uint256 privateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address caller = vm.addr(privateKey);
        AssetVault vault = _vault();
        address[] memory operators = vm.parseJsonAddressArray(_readConfig(), ".");
        bytes32 role = vault.OPERATOR_ROLE();

        _requireRoleAdmin(vault, role, caller);

        vm.startBroadcast(privateKey);
        for (uint256 i = 0; i < operators.length; ++i) {
            if (vault.hasRole(role, operators[i])) {
                console.log("OPERATOR_ROLE already granted:", operators[i]);
                continue;
            }
            vault.grantRole(role, operators[i]);
            console.log("Granted OPERATOR_ROLE:", operators[i]);
        }
        vm.stopBroadcast();
    }

    function _vault() internal returns (AssetVault vault) {
        vault = AssetVault(payable(vm.envAddress("VAULT_ADDRESS")));
        require(address(vault).code.length > 0, "VAULT_ADDRESS has no code");
    }

    function _readConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), CONFIG_PATH));
    }

    function _requireRoleAdmin(AssetVault vault, bytes32 role, address caller) internal view {
        require(vault.hasRole(vault.getRoleAdmin(role), caller), "caller cannot manage OPERATOR_ROLE");
    }
}
