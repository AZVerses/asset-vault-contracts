// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AssetVault} from "../src/AssetVault.sol";

contract DeployAssetVault is Script {
    function run() external returns (address vaultAddress, address implementationAddress) {
        uint256 deployerPrivateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        uint256 challengePeriod = vm.envOr("CHALLENGE_PERIOD", uint256(1 days));

        vm.startBroadcast(deployerPrivateKey);

        console.log("Deploying AssetVault implementation...");
        AssetVault implementation = new AssetVault();
        console.log("Implementation deployed at:", address(implementation));

        console.log("Deploying proxy...");
        bytes memory initData = abi.encodeWithSelector(AssetVault.initialize.selector, challengePeriod);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        AssetVault vault = AssetVault(payable(address(proxy)));
        console.log("Proxy deployed at:", address(vault));

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), deployer), "Admin role not set");
        require(vault.pendingWithdrawChallengePeriod() == challengePeriod, "Challenge period not set");

        console.log("Deployment completed successfully!");
        console.log("Vault address:", address(vault));
        console.log("Implementation address:", address(implementation));

        vm.stopBroadcast();

        return (address(vault), address(implementation));
    }
}
