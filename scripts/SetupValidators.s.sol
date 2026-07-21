// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script, console} from "forge-std/Script.sol";
import {AssetVault, ValidatorInfo} from "../src/AssetVault.sol";

/// @notice Adds the desired validator set and updates its required power.
/// Optional legacy sets in validators.json are removed only when explicitly listed.
contract SetupValidators is Script {
    string internal constant CONFIG_PATH = "/scripts/configs/validators.json";

    function run() external {
        uint256 privateKey = vm.envUint("AZ_DEPLOYER_PRIVATE_KEY");
        address caller = vm.addr(privateKey);
        AssetVault vault = _vault();
        string memory json = _readConfig();
        ValidatorInfo[] memory validators = _readValidators(json, ".validators");
        uint256 requiredPower = vm.parseJsonUint(json, ".requiredPower");
        bytes32 role = vault.VALIDATOR_ROLE();

        _requireRoleAdmin(vault, role, caller);
        require(requiredPower > 0 && requiredPower <= _totalPower(validators), "invalid required power");
        _requireSorted(validators);
        bool temporaryRole = !vault.hasRole(role, caller);

        vm.startBroadcast(privateKey);
        if (temporaryRole) vault.grantRole(role, caller);
        bytes32 validatorHash = keccak256(abi.encode(validators));
        if (vault.availableValidators(validatorHash) == 0) {
            vault.addValidators(validators, requiredPower);
            console.log("Added validator set");
        } else if (vault.validatorRequiredPowers(validatorHash) != requiredPower) {
            vault.updateValidatorRequiredPower(validators, requiredPower);
            console.log("Updated validator required power");
        } else {
            console.log("Validator set already configured");
        }

        uint256 legacySetCount = _arrayLength(json, ".removeValidatorSets", "validators");
        for (uint256 i = 0; i < legacySetCount; ++i) {
            ValidatorInfo[] memory legacy =
                _readValidators(json, string.concat(".removeValidatorSets.[", vm.toString(i), "].validators"));
            bytes32 legacyHash = keccak256(abi.encode(legacy));
            if (legacyHash == validatorHash || vault.availableValidators(legacyHash) == 0) {
                continue;
            }
            _requireSorted(legacy);
            vault.removeValidators(legacy);
            console.log("Removed explicitly configured legacy validator set");
        }
        if (temporaryRole) vault.revokeRole(role, caller);
        vm.stopBroadcast();
    }

    function _readValidators(string memory json, string memory base)
        internal
        view
        returns (ValidatorInfo[] memory validators)
    {
        uint256 count = _arrayLength(json, base, "signer");
        validators = new ValidatorInfo[](count);
        for (uint256 i = 0; i < count; ++i) {
            string memory item = string.concat(base, ".[", vm.toString(i), "]");
            validators[i] = ValidatorInfo({
                signer: vm.parseJsonAddress(json, string.concat(item, ".signer")),
                power: vm.parseJsonUint(json, string.concat(item, ".power"))
            });
        }
    }

    function _totalPower(ValidatorInfo[] memory validators) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < validators.length; ++i) {
            total += validators[i].power;
        }
    }

    function _requireSorted(ValidatorInfo[] memory validators) internal pure {
        address previous;
        for (uint256 i = 0; i < validators.length; ++i) {
            require(validators[i].signer > previous, "validators must be strictly sorted");
            require(validators[i].power > 0, "validator power must be nonzero");
            previous = validators[i].signer;
        }
    }

    function _arrayLength(string memory json, string memory base, string memory field)
        internal
        view
        returns (uint256 length)
    {
        while (vm.keyExistsJson(json, string.concat(base, ".[", vm.toString(length), "].", field))) ++length;
    }

    function _vault() internal returns (AssetVault vault) {
        vault = AssetVault(payable(vm.envAddress("VAULT_ADDRESS")));
        require(address(vault).code.length > 0, "VAULT_ADDRESS has no code");
    }

    function _readConfig() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), CONFIG_PATH));
    }

    function _requireRoleAdmin(AssetVault vault, bytes32 role, address caller) internal view {
        require(vault.hasRole(vault.getRoleAdmin(role), caller), "caller cannot manage VALIDATOR_ROLE");
    }
}
