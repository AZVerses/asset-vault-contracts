export type ParamKind =
  | "address"
  | "uint256"
  | "bool"
  | "bytes"
  | "bytes32"
  | "address[]"
  | "validatorTupleArray"
  | "roleHashSelect";

export type ParamDef = {
  name: string;
  label: string;
  kind: ParamKind;
  placeholder?: string;
  help?: string;
  options?: Array<{
    label: string;
    value: string;
  }>;
};

export type OperationDef = {
  id: string;
  label: string;
  role: string;
  mode: "direct" | "timelock";
  timelockType?: "admin" | "governance";
  description: string;
  functionName: string;
  functionSignature: string;
  abiJson: string;
  targetType: "vault";
  params: ParamDef[];
};

const abi = (value: string) => value;

const roleHashOptions = [
  {
    label: "DEFAULT_ADMIN_ROLE",
    value: "0x0000000000000000000000000000000000000000000000000000000000000000",
  },
  {
    label: "UPGRADE_ROLE",
    value: "0x88aa719609f728b0c5e7fb8dd3608d5c25d497efbb3b9dd64e9251ebba101508",
  },
  {
    label: "ADMIN_ROLE",
    value: "0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775",
  },
  {
    label: "TOKEN_ROLE",
    value: "0xa7197c38d9c4c7450c7f2cd20d0a17cbe7c344190d6c82a6b49a146e62439ae4",
  },
  {
    label: "VALIDATOR_ROLE",
    value: "0x21702c8af46127c7fa207f89d0b0a8441bb32959a0ac7df790e9ab1a25c98926",
  },
  {
    label: "PAUSE_ROLE",
    value: "0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d",
  },
  {
    label: "OPERATOR_ROLE",
    value: "0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929",
  },
  {
    label: "DEPOSIT_ROLE",
    value: "0x2561bf26f818282a3be40719542054d2173eb0d38539e8a8d3cff22f29fd2384",
  },
];

export const operations: OperationDef[] = [
  {
    id: "grant-role",
    label: "grantRole",
    role: "DEFAULT_ADMIN_ROLE",
    mode: "direct",
    description: "Grant a role to an address.",
    functionName: "grantRole",
    functionSignature: "grantRole(bytes32,address)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      { name: "role", label: "Role", kind: "roleHashSelect", options: roleHashOptions },
      { name: "account", label: "Account", kind: "address", placeholder: "0x..." },
    ],
  },
  {
    id: "revoke-role",
    label: "revokeRole",
    role: "DEFAULT_ADMIN_ROLE",
    mode: "direct",
    description: "Revoke a role from an address.",
    functionName: "revokeRole",
    functionSignature: "revokeRole(bytes32,address)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      { name: "role", label: "Role", kind: "roleHashSelect", options: roleHashOptions },
      { name: "account", label: "Account", kind: "address", placeholder: "0x..." },
    ],
  },
  {
    id: "upgrade-to-and-call",
    label: "upgradeToAndCall",
    role: "UPGRADE_ROLE",
    mode: "timelock",
    timelockType: "governance",
    description: "Upgrade the Vault Proxy implementation through Governance Timelock.",
    functionName: "upgradeToAndCall",
    functionSignature: "upgradeToAndCall(address,bytes)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "newImplementation",
        label: "New Implementation",
        kind: "address",
        placeholder: "0x...",
      },
      {
        name: "data",
        label: "Migration / Init Data",
        kind: "bytes",
        placeholder: "0x",
        help: "Use 0x if no migration or initialization call is required.",
      },
    ],
  },
  {
    id: "update-challenge-period",
    label: "updatePendingWithdrawChallengePeriod",
    role: "ADMIN_ROLE",
    mode: "timelock",
    timelockType: "admin",
    description: "Update the pending withdrawal challenge period through Admin Timelock.",
    functionName: "updatePendingWithdrawChallengePeriod",
    functionSignature: "updatePendingWithdrawChallengePeriod(uint256)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"uint256","name":"newValue","type":"uint256"}],"name":"updatePendingWithdrawChallengePeriod","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "newValue",
        label: "New Value (seconds)",
        kind: "uint256",
        placeholder: "86400",
      },
    ],
  },
  {
    id: "set-rebalance-receiver",
    label: "setRebalanceReceiver",
    role: "ADMIN_ROLE",
    mode: "timelock",
    timelockType: "admin",
    description: "Set the fixed rebalance receiver through Admin Timelock.",
    functionName: "setRebalanceReceiver",
    functionSignature: "setRebalanceReceiver(address)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"address","name":"newReceiver","type":"address"}],"name":"setRebalanceReceiver","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      { name: "newReceiver", label: "New Receiver", kind: "address", placeholder: "0x..." },
    ],
  },
  {
    id: "withdraw-fees",
    label: "withdrawFees",
    role: "ADMIN_ROLE",
    mode: "timelock",
    timelockType: "admin",
    description: "Withdraw accumulated protocol fees through Admin Timelock.",
    functionName: "withdrawFees",
    functionSignature: "withdrawFees(address[],address)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"address[]","name":"tokens","type":"address[]"},{"internalType":"address","name":"to","type":"address"}],"name":"withdrawFees","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "tokens",
        label: "Tokens",
        kind: "address[]",
        placeholder: "One address per line",
        help: "Use address(0) for native token.",
      },
      { name: "to", label: "Receiver", kind: "address", placeholder: "0x..." },
    ],
  },
  {
    id: "add-token",
    label: "addToken",
    role: "TOKEN_ROLE",
    mode: "direct",
    description: "Add a supported token and initialize withdrawal limits.",
    functionName: "addToken",
    functionSignature: "addToken(address,uint256,uint256)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"hardCapRatioBps","type":"uint256"},{"internalType":"uint256","name":"refillRateMps","type":"uint256"}],"name":"addToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      { name: "token", label: "Token", kind: "address", placeholder: "0x..." },
      { name: "hardCapRatioBps", label: "Hard Cap Ratio Bps", kind: "uint256", placeholder: "5000" },
      { name: "refillRateMps", label: "Refill Rate Mps", kind: "uint256", placeholder: "12" },
    ],
  },
  {
    id: "update-token",
    label: "updateToken",
    role: "TOKEN_ROLE",
    mode: "direct",
    description: "Update withdrawal capacity parameters for a supported token.",
    functionName: "updateToken",
    functionSignature: "updateToken(address,uint256,uint256)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"hardCapRatioBps","type":"uint256"},{"internalType":"uint256","name":"refillRateMps","type":"uint256"}],"name":"updateToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      { name: "token", label: "Token", kind: "address", placeholder: "0x..." },
      { name: "hardCapRatioBps", label: "Hard Cap Ratio Bps", kind: "uint256", placeholder: "4000" },
      { name: "refillRateMps", label: "Refill Rate Mps", kind: "uint256", placeholder: "10" },
    ],
  },
  {
    id: "add-validators",
    label: "addValidators",
    role: "VALIDATOR_ROLE",
    mode: "direct",
    description:
      "Add a validator set and required power. For rotation, batch this before removeValidators(oldSet) in the same Safe transaction.",
    functionName: "addValidators",
    functionSignature: "addValidators((address,uint256)[],uint256)",
    abiJson: abi(
      '[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"},{"internalType":"uint256","name":"requiredPower","type":"uint256"}],"name":"addValidators","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "validators",
        label: "Validators",
        kind: "validatorTupleArray",
        help: "Must be in strict ascending signer address order. For rotation, this add call must come before the old-set remove call in the same Safe batch.",
      },
      { name: "requiredPower", label: "Required Power", kind: "uint256", placeholder: "40" },
    ],
  },
  {
    id: "update-validator-required-power",
    label: "updateValidatorRequiredPower",
    role: "VALIDATOR_ROLE",
    mode: "direct",
    description: "Update required power for an existing validator set.",
    functionName: "updateValidatorRequiredPower",
    functionSignature: "updateValidatorRequiredPower((address,uint256)[],uint256)",
    abiJson: abi(
      '[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"},{"internalType":"uint256","name":"newRequiredPower","type":"uint256"}],"name":"updateValidatorRequiredPower","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "validators",
        label: "Validators",
        kind: "validatorTupleArray",
        help: "Must match the existing on-chain validator set exactly.",
      },
      { name: "newRequiredPower", label: "New Required Power", kind: "uint256", placeholder: "60" },
    ],
  },
  {
    id: "remove-validators",
    label: "removeValidators",
    role: "VALIDATOR_ROLE",
    mode: "direct",
    description:
      "Remove a validator set. For rotation, do not submit this standalone; batch it after addValidators(newSet) in the same Safe transaction.",
    functionName: "removeValidators",
    functionSignature: "removeValidators((address,uint256)[])",
    abiJson: abi(
      '[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"}],"name":"removeValidators","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [
      {
        name: "validators",
        label: "Validators",
        kind: "validatorTupleArray",
        help: "For rotation, batch this after addValidators(newSet) in the same Safe transaction, and confirm signing services have switched.",
      },
    ],
  },
  {
    id: "toggle",
    label: "toggle",
    role: "PAUSE_ROLE",
    mode: "direct",
    description: "Pause or unpause the vault.",
    functionName: "toggle",
    functionSignature: "toggle(bool)",
    abiJson: abi(
      '[{"inputs":[{"internalType":"bool","name":"pause","type":"bool"}],"name":"toggle","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
    ),
    targetType: "vault",
    params: [{ name: "pause", label: "Pause", kind: "bool" }],
  },
];

export const timelockAbis = {
  schedule: abi(
    '[{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"bytes32","name":"predecessor","type":"bytes32"},{"internalType":"bytes32","name":"salt","type":"bytes32"},{"internalType":"uint256","name":"delay","type":"uint256"}],"name":"schedule","outputs":[],"stateMutability":"nonpayable","type":"function"}]',
  ),
  execute: abi(
    '[{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"bytes32","name":"predecessor","type":"bytes32"},{"internalType":"bytes32","name":"salt","type":"bytes32"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}]',
  ),
};
