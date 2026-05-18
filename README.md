# Asset Vault Contracts

## Project Overview

`AssetVault` is the custody and withdrawal settlement contract for the exchange.

It serves four purposes:

- hold supported assets, including ERC-20 and native token
- settle normal withdrawals through a validator-authorized flow
- split withdrawals into a fast path and a slow path
- provide explicit operational controls for pausing, flushing, emergency withdrawal, and upgrade

The contract is UUPS-upgradeable and built around role-based access control plus validator quorum verification.

## Roles

### `DEFAULT_ADMIN_ROLE`

- grants and revokes all roles
- highest authority in the role tree

### `ADMIN_ROLE`

- updates `pendingWithdrawChallengePeriod`
- updates supported token risk parameters
- sets `rebalanceReceiver`
- withdraws accumulated fees
- performs `emergencyWithdraw`

### `VALIDATOR_ROLE`

- adds validator sets
- updates validator required power
- removes validator sets

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

Outcome:

- if the request stays within hot-withdraw capacity and is not force-pending, it executes immediately as a fast withdrawal
- otherwise it enters the slow queue as a pending withdrawal

### `batchTogglePendingWithdrawal`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- validator signatures must satisfy the configured validator set and required power
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

- emits `DepositOnBehalf(caller, forAccount, token, amount)`
- `forAccount` is event attribution only; the vault does not maintain a per-user balance ledger

### `rebalanceWithdraw`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- token must be supported
- vault must have enough balance
- `rebalanceReceiver` must be set
- validator signatures must satisfy the configured validator set and required power

Behavior:

- transfers assets to the configured `rebalanceReceiver`
- does not enter the slow queue
- does not consume hot-withdraw capacity

### `batchResetWithdrawHotAmount`

Conditions:

- caller must have `OPERATOR_ROLE`
- vault must not be globally paused
- validator signatures must satisfy the configured validator set and required power
- each token must be supported

Behavior:

- resets `usedWithdrawHotAmount` to zero for each token

### `withdrawFees`

Conditions:

- caller must have `ADMIN_ROLE`
- vault must not be globally paused

Behavior:

- transfers accumulated fees out of the vault

### `emergencyWithdraw`

Conditions:

- caller must have `ADMIN_ROLE`
- vault must not be globally paused
- receiver must not be zero address

Behavior:

- transfers vault assets directly to the given receiver

This is not a lightweight admin action. It is direct asset movement authority.

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
