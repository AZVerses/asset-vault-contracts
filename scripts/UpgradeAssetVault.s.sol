// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Usage:
// forge script scripts/UpgradeAssetVault.s.sol:UpgradeAssetVault --rpc-url <RPC_URL> --broadcast --verify --verifier-url <VERIFIER_URL> --chain <CHAIN_ID> --etherscan-api-key <API_KEY>
//
// Environment variables:
// - AZ_DEPLOYER_PRIVATE_KEY: Private key of the account with UPGRADE_ROLE
// - VAULT_ADDRESS: Address of the deployed AssetVault proxy
// - NEW_IMPLEMENTATION_ADDRESS (optional): If provided, will use this address instead of deploying new implementation

import {Script, console} from "forge-std/Script.sol";
import {AssetVault} from "../src/AssetVault.sol";

contract UpgradeAssetVault is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address vaultAddress = vm.envAddress("VAULT_ADDRESS");

        AssetVault vault = AssetVault(payable(vaultAddress));

        vm.startBroadcast(deployerPrivateKey);

        // Deploy new implementation
        console.log("Deploying new AssetVault implementation...");
        AssetVault implementation = new AssetVault();
        console.log("New implementation deployed at:", address(implementation));
        // Perform upgrade
        console.log("Upgrading proxy to new implementation...");
        vault.upgradeToAndCall(address(implementation), "");
        console.log("Upgrade completed successfully!");

        vm.stopBroadcast();
    }
}
