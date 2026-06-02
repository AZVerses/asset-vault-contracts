# AssetVault Ops Web

Static React tool for production operators.

It supports:

- per-chain fixed `Vault Proxy`, `Admin Timelock`, and `Governance Timelock` targets
- whitelisted multisig operations only
- ABI JSON display for each operation
- calldata encode for direct Safe actions
- two-step calldata encode for `ADMIN_ROLE` and `UPGRADE_ROLE` actions through OpenZeppelin `TimelockController`
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

Current timelock addresses in the app are placeholders and must be replaced after deployment.
