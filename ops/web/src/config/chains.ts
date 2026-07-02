export type ChainConfig = {
  id: string;
  name: string;
  chainId: number;
  vaultProxy: string;
  adminTimelock: TimelockConfig;
  governanceTimelock: TimelockConfig;
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
    vaultProxy: "0xAB3D96237328385f8988166c6d7788a63f48dDa6",
    adminTimelock: {
      address: "0x1111111111111111111111111111111111111111",
      delaySeconds: 259200,
    },
    governanceTimelock: {
      address: "0x4444444444444444444444444444444444444444",
      delaySeconds: 259200,
    },
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
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
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
];
