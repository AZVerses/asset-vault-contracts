# AssetVault Ops Web

Static React tool for production operators.

It supports:

- per-chain fixed `Vault Proxy`, `Admin Timelock`, `Governance Timelock`, and `Upgrade Timelock` targets
- whitelisted multisig operations only
- ABI JSON display for each operation
- calldata encode for direct Safe actions
- two-step calldata encode for `DEFAULT_ADMIN_ROLE`, `ADMIN_ROLE`, and `UPGRADE_ROLE` actions through OpenZeppelin `TimelockController`
- manual Timelock `operation id` input for cancel flows
- calldata decode for pasted direct or timelock calldata

## Local development

```bash
npm install
npm run dev
```

## Production build

```bash
npm run build
```

## Vercel

- Framework preset: `Vite`
- Root directory: `ops/web`
- Build command: `npm run build`
- Output directory: `dist`

Arbitrum One is configured with the deployed production Vault Proxy and three
Timelocks: Admin `1800s`, Governance `259200s`, and Upgrade `259200s`.
Arbitrum Sepolia and Ethereum Sepolia remain placeholder configurations until
those deployments are completed.
