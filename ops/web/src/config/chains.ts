export type ChainConfig = {
  id: string;
  name: string;
  chainId: number;
  vaultProxy: string;
  adminTimelock: string;
  governanceTimelock: string;
  timelockDelaySeconds: number;
  addressNote: string;
};

export const ZERO_HASH =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

export const chains: ChainConfig[] = [
  {
    id: "arb1",
    name: "Arbitrum One",
    chainId: 42161,
    vaultProxy: "0xAB3D96237328385f8988166c6d7788a63f48dDa6",
    adminTimelock: "0x1111111111111111111111111111111111111111",
    governanceTimelock: "0x4444444444444444444444444444444444444444",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
  {
    id: "arb-sepolia",
    name: "Arbitrum Sepolia",
    chainId: 421614,
    vaultProxy: "0xf2137a2d64ba4dafcab54959862f7384ed7be100",
    adminTimelock: "0x2222222222222222222222222222222222222222",
    governanceTimelock: "0x5555555555555555555555555555555555555555",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
  {
    id: "eth-sepolia",
    name: "Ethereum Sepolia",
    chainId: 11155111,
    vaultProxy: "0xcae91ee34ef8a1076229d9e6dbc6b1ec6248671d",
    adminTimelock: "0x3333333333333333333333333333333333333333",
    governanceTimelock: "0x6666666666666666666666666666666666666666",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Timelock addresses. Replace after deployment.",
  },
];
