// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AssetVault} from "../src/AssetVault.sol";

/// @notice Adds or updates tokens from scripts/configs/tokens.json.
/// The JSON file is the only source of token addresses and risk parameters.
contract SetupTokens is Script {
    string internal constant CONFIG_PATH = "/scripts/configs/tokens.json";

    struct TokenConfig {
        address token;
        string label;
        string expectedName;
        string expectedSymbol;
        uint256 expectedDecimals;
        uint256 hardCapRatioBps;
        uint256 refillRateMps;
    }

    function run() external {
        uint256 privateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address caller = vm.addr(privateKey);
        AssetVault vault = _vault();
        string memory json = _readConfig();
        uint256 count = _arrayLength(json, ".", "token");
        bytes32 role = vault.TOKEN_ROLE();

        _requireRoleAdmin(vault, role, caller);
        bool temporaryRole = !vault.hasRole(role, caller);

        vm.startBroadcast(privateKey);
        if (temporaryRole) vault.grantRole(role, caller);
        for (uint256 i = 0; i < count; ++i) {
            TokenConfig memory config = _readToken(json, i);
            _validateConfig(config);
            _validateToken(config);

            (, uint256 currentCap, uint256 currentRefill,,) = vault.supportedTokens(config.token);
            if (currentCap == 0) {
                vault.addToken(config.token, config.hardCapRatioBps, config.refillRateMps);
                console.log("Added token:", config.label, config.token);
            } else if (currentCap != config.hardCapRatioBps || currentRefill != config.refillRateMps) {
                vault.updateToken(config.token, config.hardCapRatioBps, config.refillRateMps);
                console.log("Updated token:", config.label, config.token);
            } else {
                console.log("Token already configured:", config.label, config.token);
            }
        }
        if (temporaryRole) vault.revokeRole(role, caller);
        vm.stopBroadcast();
    }

    function _readToken(string memory json, uint256 index) internal view returns (TokenConfig memory config) {
        string memory base = string.concat(".[", vm.toString(index), "]");
        config.token = vm.parseJsonAddress(json, string.concat(base, ".token"));
        config.label = vm.parseJsonString(json, string.concat(base, ".label"));
        config.expectedName = vm.parseJsonString(json, string.concat(base, ".expectedName"));
        config.expectedSymbol = vm.parseJsonString(json, string.concat(base, ".expectedSymbol"));
        config.expectedDecimals = vm.parseJsonUint(json, string.concat(base, ".expectedDecimals"));
        config.hardCapRatioBps = vm.parseJsonUint(json, string.concat(base, ".hardCapRatioBps"));
        config.refillRateMps = vm.parseJsonUint(json, string.concat(base, ".refillRateMps"));
    }

    function _validateConfig(TokenConfig memory config) internal pure {
        require(config.hardCapRatioBps > 0 && config.hardCapRatioBps <= 10_000, "invalid hard cap ratio");
        require(config.refillRateMps > 0 && config.refillRateMps <= 1_000_000, "invalid refill rate");
        require(config.expectedDecimals <= 255, "invalid decimals");
    }

    function _validateToken(TokenConfig memory config) internal view {
        if (config.token == address(0)) {
            return;
        }
        require(config.token.code.length > 0, "token has no bytecode");
        IERC20(config.token).totalSupply();
        require(
            keccak256(bytes(IERC20Metadata(config.token).name())) == keccak256(bytes(config.expectedName)),
            "token name mismatch"
        );
        require(
            keccak256(bytes(IERC20Metadata(config.token).symbol())) == keccak256(bytes(config.expectedSymbol)),
            "token symbol mismatch"
        );
        require(IERC20Metadata(config.token).decimals() == config.expectedDecimals, "token decimals mismatch");
    }

    function _arrayLength(string memory json, string memory base, string memory field)
        internal
        view
        returns (uint256 length)
    {
        while (vm.keyExistsJson(json, string.concat(base, ".[", vm.toString(length), "].", field))) {
            ++length;
        }
    }

    function _vault() internal returns (AssetVault vault) {
        vault = AssetVault(payable(vm.envAddress("VAULT_ADDRESS")));
        require(address(vault).code.length > 0, "VAULT_ADDRESS has no code");
    }

    function _readConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), CONFIG_PATH));
    }

    function _requireRoleAdmin(AssetVault vault, bytes32 role, address caller) internal view {
        require(vault.hasRole(vault.getRoleAdmin(role), caller), "caller cannot manage TOKEN_ROLE");
    }
}
