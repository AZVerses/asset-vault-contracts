export type ChainConfig = {
  id: string;
  name: string;
  chainId: number;
  vaultProxy: string;
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
    vaultProxy: "0xf105063609cbd63977d9c2bee0142c10fe3d27e8",
    governanceTimelock: "0x1111111111111111111111111111111111111111",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Governance Timelock address. Replace after deployment.",
  },
  {
    id: "arb-sepolia",
    name: "Arbitrum Sepolia",
    chainId: 421614,
    vaultProxy: "0xf2137a2d64ba4dafcab54959862f7384ed7be100",
    governanceTimelock: "0x2222222222222222222222222222222222222222",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Governance Timelock address. Replace after deployment.",
  },
  {
    id: "eth-sepolia",
    name: "Ethereum Sepolia",
    chainId: 11155111,
    vaultProxy: "0xcae91ee34ef8a1076229d9e6dbc6b1ec6248671d",
    governanceTimelock: "0x3333333333333333333333333333333333333333",
    timelockDelaySeconds: 259200,
    addressNote: "Placeholder Governance Timelock address. Replace after deployment.",
  },
];
