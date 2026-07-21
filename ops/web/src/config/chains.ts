export type ChainConfig = {
  id: string;
  name: string;
  chainId: number;
  vaultProxy: string;
  adminTimelock: TimelockConfig;
  governanceTimelock: TimelockConfig;
  upgradeTimelock: TimelockConfig;
  addressNote: string;
};

export type TimelockConfig = {
  address: string;
  delaySeconds: number;
};

export const ZERO_HASH =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

export const chains: ChainConfig[] = [
  {
    id: "arb1",
    name: "Arbitrum One",
    chainId: 42161,
    vaultProxy: "0x91Ba525861c16AA8Cd4D6974E4058cc846f42eBE",
    adminTimelock: {
      address: "0xb9CC7c15BD18FBBE1a8c0F3F49A4F3D10f193495",
      delaySeconds: 259200,
    },
    governanceTimelock: {
      address: "0xe78A0079071f4C4e7A9280dBd6b3476Ac6Bf85c6",
      delaySeconds: 259200,
    },
    upgradeTimelock: {
      address: "0xAA5A98c2b6340b3d05Bc63ef578f1bc330100f3c",
      delaySeconds: 259200,
    },
    addressNote: "Arbitrum One production addresses; all Timelocks use a 72h delay.",
  },
  {
    id: "arb-sepolia",
    name: "Arbitrum Sepolia",
    chainId: 421614,
    vaultProxy: "0xf2137a2d64ba4dafcab54959862f7384ed7be100",
    adminTimelock: {
      address: "0x2222222222222222222222222222222222222222",
      delaySeconds: 259200,
    },
    governanceTimelock: {
      address: "0x5555555555555555555555555555555555555555",
      delaySeconds: 259200,
    },
    upgradeTimelock: {
      address: "0x7777777777777777777777777777777777777777",
      delaySeconds: 259200,
    },
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
  {
    id: "eth-sepolia",
    name: "Ethereum Sepolia",
    chainId: 11155111,
    vaultProxy: "0xcae91ee34ef8a1076229d9e6dbc6b1ec6248671d",
    adminTimelock: {
      address: "0x3333333333333333333333333333333333333333",
      delaySeconds: 259200,
    },
    governanceTimelock: {
      address: "0x6666666666666666666666666666666666666666",
      delaySeconds: 259200,
    },
    upgradeTimelock: {
      address: "0x8888888888888888888888888888888888888888",
      delaySeconds: 259200,
    },
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
];
