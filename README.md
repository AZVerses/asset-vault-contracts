# Asset Vault Contracts

## Project Overview

`AssetVault` is the custody and withdrawal settlement contract for the exchange.

It serves four purposes:

- hold supported assets, including ERC-20 and native token
- settle normal withdrawals through a validator-authorized flow
- split withdrawals into a fast path and a slow path
- provide explicit operational controls for pausing, flushing, rebalance payout control, and upgrade

## Scripts

The setup entrypoints are intentionally split by responsibility. All scripts require
`AZ_DEPLOYER_PRIVATE_KEY`; setup scripts also require `VAULT_ADDRESS`. The RPC URL is
passed to Foundry with `--rpc-url`.

```bash
forge script scripts/DeployAssetVault.s.sol:DeployAssetVault --rpc-url "$RPC_URL" --broadcast
forge script scripts/SetupOperators.s.sol:SetupOperators --rpc-url "$RPC_URL" --broadcast
forge script scripts/SetupTokens.s.sol:SetupTokens --rpc-url "$RPC_URL" --broadcast
forge script scripts/SetupValidators.s.sol:SetupValidators --rpc-url "$RPC_URL" --broadcast
forge script scripts/SetupAdminRoles.s.sol:SetupAdminRoles --rpc-url "$RPC_URL" --broadcast
```

`DeployAssetVault` uses `CHALLENGE_PERIOD` when provided and defaults to one day.
The other retained utilities are `UpgradeAssetVault`, `generateTypes.ts`, and
`calculateBytecodeSize.ts`.

Configuration files:

- `scripts/configs/tokens.json`: local ERC-20/native token address, metadata expectations,
  hard-cap ratio, and refill rate. Existing tokens are updated; missing tokens are added.
- `scripts/configs/operators.json`: local operator addresses. Existing grants are skipped.
- `scripts/configs/validators.json`: local desired sorted validator set and required power.
  Old sets are removed only when explicitly listed under `removeValidatorSets` because
  `AssetVault` does not expose an enumerable current validator set.
- `scripts/configs/roles.json`: local role name/hash, direct holders, and optional
  timelock settings. `roleHashL` is accepted as a compatibility alias for `roleHash`.

The real JSON files are ignored by git. Copy the templates before configuring a
deployment:

```bash
cp scripts/configs/tokens.example.json scripts/configs/tokens.json
cp scripts/configs/operators.example.json scripts/configs/operators.json
cp scripts/configs/validators.example.json scripts/configs/validators.json
cp scripts/configs/roles.example.json scripts/configs/roles.json
```

The example addresses are placeholders and must be replaced before broadcasting.

For a timelocked role, `roles` are proposer candidates and the vault role is granted to
the `TimelockController`; proposer defaults to the first entry, canceller defaults to
the proposer, and executor defaults to the current setup caller. An existing
`timelockAddress` must use the configured delay; a zero address causes a new controller
to be deployed and its emitted address must be written back to the JSON before rerunning.
The controller follows OpenZeppelin Contracts v5.6.1 `TimelockController` semantics:
<https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/governance/TimelockController.sol>.

The contract is UUPS-upgradeable and built around role-based access control plus validator quorum verification.

## Signature And Nonce Rules

Validator-authorized operations in `AssetVault` do **not** use EIP-712 typed data.

- the contract hashes business fields with `keccak256(abi.encode(...))`
- the validator signature check then applies `toEthSignedMessageHash`
- in wallet / infra terminology, this is `personal_sign` / EIP-191 style signing

Nonce handling is also intentionally **non-sequential**.

- the contract only checks whether a nonce has already been used
- any unused `uint256` nonce is valid
- nonces do not need to be continuous, increasing, or gap-free

Operationally, monitoring and off-chain services must treat nonce as a one-time unique identifier, not as a sequential counter.

## Roles

### `DEFAULT_ADMIN_ROLE`

- grants and revokes all roles
- highest authority in the role tree
- production holder should be timelock-backed, not a direct Safe holder

### `ADMIN_ROLE`

- updates `pendingWithdrawChallengePeriod`
- sets `rebalanceReceiver`
- withdraws accumulated fees

### `VALIDATOR_ROLE`

- adds validator sets
- updates validator required power
- removes validator sets

Validator rotation rule:

- rotate validators with one Safe batch transaction that calls `addValidators(newSet, newRequiredPower)` first and `removeValidators(oldSet)` second
- do not submit standalone `removeValidators` during rotation
- the goal is to minimize downtime while also minimizing the window where multiple validator sets are simultaneously valid
- signing services must switch to the new validator set before the batch is signed

### `TOKEN_ROLE`

- adds supported tokens

### `OPERATOR_ROLE`

- submits validator-authorized withdrawals
- pauses or unpauses pending withdrawals
- flushes pending withdrawals
- resets hot-withdraw usage
- executes validator-authorized rebalance withdrawals

`OPERATOR_ROLE` alone is not enough for these sensitive paths. The withdrawal, flush, toggle, rebalance, and reset-hot-amount actions all require validator signatures that meet the configured required power.

### `DEPOSIT_ROLE`

- calls `depositOnBehalf`

This is a whitelisted ingress path for ERC-20 or native deposits that need an explicit `forAccount` attribution in the event log.

### `PAUSE_ROLE`

- pauses or unpauses the whole vault through `toggle`

### `UPGRADE_ROLE`

- upgrades the implementation through `upgradeToAndCall`

## Token Model

Each supported token has:

- `hardCapRatioBps`
- `refillRateMps`
- `lastRefillTimestamp`
- `usedWithdrawHotAmount`

`hardCap` is calculated from current vault balance:

- `hardCap = vaultBalance * hardCapRatioBps / 10000`

`usedWithdrawHotAmount` tracks how much fast-withdraw capacity has been consumed.

Over time, that usage decays according to `refillRateMps`. This is what allows fast withdrawals to recover capacity without manual intervention.

The contract applies `hardCap * refillRateMps * elapsedSeconds / 1_000_000`.
For recovery within 24 hours, `ceil(1_000_000 / 86_400) = 12` is used in
`scripts/configs/tokens.json`; this reaches 100% in about 83,334 seconds rather
than exactly 86,400 seconds because the rate is an integer.

## Fast Queue And Slow Queue

### Fast queue

A withdrawal stays on the fast path when:

- it is not force-pending
- and adding its amount does not make `usedWithdrawHotAmount` exceed `hardCap`

Fast-path withdrawal behavior:

- validator signatures are still required
- the withdrawal is executed immediately in the same transaction
- `usedWithdrawHotAmount` is increased
- no challenge period applies

### Slow queue

A withdrawal enters the slow path when:

- `isForcePending == true`
- or the requested amount would push `usedWithdrawHotAmount` over `hardCap`

Slow-path withdrawal behavior:

- a `Withdrawal` record is created with `pending = true`
- the withdrawal is not executed immediately
- it is governed by `pendingWithdrawChallengePeriod`
- it can also be explicitly `paused`

Do not confuse the two controls:

- challenge period controls time-based release
- paused flag controls manual freeze

`flush` can bypass challenge-period expiry, but it cannot bypass the paused flag.

## Operational Rules

### `requestWithdraw`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- token must be supported
- vault must have enough balance
- validator signatures must satisfy the configured validator set and required power
- nonce must be unused
- nonce does not need to be sequential

Outcome:

- if the request stays within hot-withdraw capacity and is not force-pending, it executes immediately as a fast withdrawal
- otherwise it enters the slow queue as a pending withdrawal

### `batchTogglePendingWithdrawal`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- validator signatures must satisfy the configured validator set and required power
- nonce must be unused
- nonce does not need to be sequential
- each withdrawal must exist
- each withdrawal must be pending
- each withdrawal must not be executed
- target state must differ from current state

State rules:

- before challenge-period expiry, pending withdrawals can be paused or unpaused
- after challenge-period expiry, pending withdrawals can still be unpaused
- after challenge-period expiry, pending withdrawals cannot be newly paused

This rule matters because post-expiry review may clear a withdrawal, and the system must allow `unpause -> execute`.

### `batchFlushWithdrawals`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- validator signatures must satisfy the configured validator set and required power
- nonce must be unused
- nonce does not need to be sequential
- each withdrawal must exist
- each withdrawal must be pending
- each withdrawal must not be executed
- each withdrawal must not be paused

Behavior:

- flush does not require challenge-period expiry
- flush is allowed before expiry
- flush is also allowed after expiry
- flush does not override a paused withdrawal

In short:

- `pending + not paused + not expired` -> can flush
- `pending + not paused + expired` -> can flush
- `pending + paused` -> cannot flush

### `executeExpiredPendingWithdrawal`

Conditions:

- vault must not be globally paused
- withdrawal must exist
- withdrawal must be pending
- withdrawal must not be executed
- withdrawal must not be paused
- challenge period must already be expired

Behavior:

- this is permissionless once the above conditions are satisfied
- anyone can execute the pending withdrawal

In short:

- `pending + not paused + expired` -> can execute
- `pending + paused + expired` -> cannot execute; must unpause first

### `depositOnBehalf`

Conditions:

- caller must have `DEPOSIT_ROLE`
- vault must not be globally paused
- `forAccount` must not be zero address
- `amount` must be non-zero
- token must be supported

ERC-20 path:

- `msg.value` must be zero
- contract pulls funds with `safeTransferFrom`

Native path:

- token must be `address(0)`
- `msg.value` must equal `amount`

Behavior:

- emits `DepositOnBehalf(caller, forAccount, token, amount, data)`
- `forAccount` is event attribution only; the vault does not maintain a per-user balance ledger

### `rebalanceWithdraw`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- token must be supported
- vault must have enough balance
- `rebalanceReceiver` must be set
- validator signatures must satisfy the configured validator set and required power
- nonce must be unused
- nonce does not need to be sequential

Behavior:

- transfers assets to the configured `rebalanceReceiver`
- the interface has no `fee` parameter and rebalance does not accrue protocol fees
- does not enter the slow queue
- does not consume hot-withdraw capacity

### `batchResetWithdrawHotAmount`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- validator signatures must satisfy the configured validator set and required power
- nonce must be unused
- nonce does not need to be sequential
- each token must be supported

Behavior:

- resets `usedWithdrawHotAmount` to zero for each token
- reuses the `WithdrawHotAmountRefilled` event for observability
- on this reset path, the event's `refillAmount` field means the pre-reset `usedWithdrawHotAmount`, not a time-based refill amount
- off-chain monitoring and analytics must distinguish reset-triggered events from natural refill-triggered events by transaction function context

### `withdrawFees`

Conditions:

- caller must have `ADMIN_ROLE`
- vault must not be globally paused

Behavior:

- transfers accumulated fees out of the vault

### `toggle`

Conditions:

- caller must have `PAUSE_ROLE`

Behavior:

- pauses or unpauses the whole vault
- while globally paused, protected external operations using `whenNotPaused` are blocked

## Summary Of Slow-Queue Semantics

The current intended behavior is:

- slow queue paused, challenge period not expired: cannot flush, cannot execute
- slow queue not paused, challenge period not expired: can flush, cannot execute
- slow queue paused, challenge period expired: cannot flush, cannot execute; must unpause first
- slow queue not paused, challenge period expired: can flush, can execute

This means:

- `paused` is an absolute freeze for the pending withdrawal itself
- `flush` is an override for time, not an override for pause
- `execute` is the normal release path after the challenge period
