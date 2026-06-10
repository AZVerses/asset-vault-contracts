# AssetVault 生产操作手册（中文草案）

本文档面向生产环境操作者、签名人和审核人，覆盖：

- `AssetVault` 的权限治理结构
- 各角色可执行函数及其实际含义
- 生产操作前的安全检查
- Safe 网页端的填写方式
- Lark 审批流程要求

`ADMIN_ROLE` 和 `UPGRADE_ROLE` 必须经过 Timelock，其余高权限操作为 Safe 直连 `Vault Proxy`。

# 治理结构

当前建议的治理拆分如下：

- `Governance Safe (4/7)` -> `Governance Timelock (72h)` -> `UPGRADE_ROLE`
- `Governance Safe (4/7)` -> `DEFAULT_ADMIN_ROLE`
- `Admin Safe (4/7)` -> `Admin Timelock (72h)` -> `ADMIN_ROLE`
- `Token Safe (4/7)` -> `TOKEN_ROLE`
- `Validator Safe (4/7)` -> `VALIDATOR_ROLE`
- `Emergency Guardian Safe (3/5)` -> `PAUSE_ROLE`
- `Operator KMS` -> `OPERATOR_ROLE`
- `Deposit Service Wallet` -> `DEPOSIT_ROLE`

关键说明：

- 只有 `UPGRADE_ROLE` 负责合约升级，且必须经过 Timelock。
- `ADMIN_ROLE` 负责挑战期、rebalance receiver 和手续费提取，也必须经过 Timelock。
- `DEFAULT_ADMIN_ROLE` 不负责合约升级。
- `TOKEN_ROLE`、`VALIDATOR_ROLE`、`PAUSE_ROLE` 是 Safe 直连 `Vault Proxy`。
- validator 轮换时，必须先 `addValidators`，确认新集合可用后，再 `removeValidators` 旧集合。

# 基础安全规范

## 基础原则

- 所有生产操作必须通过 Safe 或 Safe + Timelock 执行，禁止生产 EOA 直连高权限函数。
- 任何签名人都不能盲签，必须独立核对网页参数和 Safe 自动生成的 calldata。
- Safe 域名、链 ID、Safe 地址、Vault Proxy 地址、Timelock 地址、目标 receiver 地址都要逐项核对。
- 生产签名只允许在专用设备上完成，且必须使用硬件钱包。
- 新地址、新 token、新 validator、新 implementation 不能只看聊天窗口或截图，必须从可信来源交叉核验。
- 每次执行后都要做链上状态回读和事件校验，不能只看交易 `Success`。

## 执行前安全检查

- 只从书签或手工输入访问 Safe，域名应为 `https://app.safe.global`。
- 检查浏览器地址栏证书是否正常，避免在仿冒站点签名。
- 检查当前连接的钱包是不是本次应使用的硬件钱包。
- 检查 Safe 页面左上角展示的链和 Safe 地址，确认不是测试网、不是其他 Safe。
- 检查 `To` 地址到底是 `Vault Proxy`、`Admin Timelock` 还是 `Governance Timelock`，不要填反。
- 对于新的 receiver / treasury / validator / implementation 地址，至少做两种独立来源核验：
  - 官方官网、官方文档、官方 GitHub、官方公告
  - 区块浏览器已验证合约页面
  - 内部资产地址台账
- 对于 implementation 地址，必须确认：
  - implementation 合约必须 audit 过
  - 目标地址上确实有代码
  - 源码已验证或来源可追溯
  - 存储布局兼容性已审过
- 对于 token 地址，必须确认：
  - 链正确
  - decimals 正确
  - 是官方 token，不是同名假币

## 其他日常安全要求

- 不要在 IM 聊天里直接发“最新地址”，要发可追溯来源和用途说明。
- 新的收款地址在首次大额使用前，建议先做一笔小额验证。
- 生产机器不要安装不必要插件，尤其是钱包增强类、脚本注入类、剪贴板类插件。
- 不要在签名前后复制未校验的十六进制 calldata 给其他人“帮忙看一下”，应附带函数签名和参数释义。
- 每月度至少做一次 signer、receiver 白名单、validator 集合、地址台账复核。

## Lark 审批流程

- 所有生产高权限操作都应先走 Lark 审批流程，再进入 Safe 或 Safe + Timelock 执行。
- 审批记录至少应包含：操作名称、目标链、目标合约、目标函数、参数明细、业务原因、风险说明、交易哈希。
- Timelock 操作应额外记录：`salt`、`schedule` 交易哈希、`execute` 交易哈希。
- Lark 审批记录应能和最终链上交易一一对应，便于回溯。

# 链上地址

## Vault Proxy

- Arbitrum One `42161`
  - Vault Proxy: `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Arbitrum Sepolia `421614`
  - Vault Proxy: `0xf2137a2d64ba4dafcab54959862f7384ed7be100`
- Ethereum Sepolia `11155111`
  - Vault Proxy: `0xcae91ee34ef8a1076229d9e6dbc6b1ec6248671d`

## Safe / Timelock 地址

以下地址在正式下发给运营前必须补齐：

- `Governance Safe`
- `Governance Timelock`
- `Admin Safe`
- `Admin Timelock`
- `Token Safe`
- `Validator Safe`
- `Emergency Guardian Safe`

# Roles

## DEFAULT_ADMIN_ROLE

- Holder: `Governance Safe`
- Upstream signer threshold: `4/7`
- Hash ID: `0x0000000000000000000000000000000000000000000000000000000000000000`
- Responsibilities:
  - `grantRole(bytes32,address)`: 给指定地址授予某个角色，使该地址获得对应管理权限。
  - `revokeRole(bytes32,address)`: 回收指定地址上的某个角色，禁止其继续调用对应权限函数。

## UPGRADE_ROLE

- Holder: `Governance Timelock (72h)`
- Upstream signer threshold: `Governance Safe 4/7`
- Hash ID: `0x88aa719609f728b0c5e7fb8dd3608d5c25d497efbb3b9dd64e9251ebba101508`
- Responsibilities:
  - `upgradeToAndCall(address,bytes)`: 把 Vault Proxy 升级到新的 implementation，并可选执行一次迁移或初始化 calldata。

## ADMIN_ROLE

- Holder: `Admin Timelock (72h)`
- Upstream signer threshold: `Admin Safe 4/7`
- Hash ID: `0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775`
- Responsibilities:
  - `updatePendingWithdrawChallengePeriod(uint256)`: 修改 pending withdrawal 的挑战期长度。
  - `setRebalanceReceiver(address)`: 设置 `rebalanceWithdraw` 使用的固定收款地址。
  - `withdrawFees(address[],address)`: 提走协议累计手续费。

## TOKEN_ROLE

- Holder: `Token Safe`
- Upstream signer threshold: `4/7`
- Hash ID: `0xa7197c38d9c4c7450c7f2cd20d0a17cbe7c344190d6c82a6b49a146e62439ae4`
- Responsibilities:
  - `addToken(address,uint256,uint256)`: 新增支持的 token，并初始化快提额度比例和额度回补速度。
  - `updateToken(address,uint256,uint256)`: 调整已支持 token 的快提额度比例和回补速度。

## VALIDATOR_ROLE

- Holder: `Validator Safe`
- Upstream signer threshold: `4/7`
- Hash ID: `0x21702c8af46127c7fa207f89d0b0a8441bb32959a0ac7df790e9ab1a25c98926`
- Responsibilities:
  - `addValidators((address,uint256)[],uint256)`: 新增一组 validator 集合，并设置该集合通过校验所需的最小 power。
  - `updateValidatorRequiredPower((address,uint256)[],uint256)`: 不改 validator 成员，只调整这组 validator 的通过门槛。
  - `removeValidators((address,uint256)[])`: 删除一组 validator 集合。

## PAUSE_ROLE

- Holder: `Emergency Guardian Safe`
- Upstream signer threshold: `3/5`
- Hash ID: `0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d`
- Responsibilities:
  - `toggle(bool)`: 全局暂停或恢复 Vault 的可写核心功能。

## OPERATOR_ROLE

- Holder: `Operator KMS`
- Upstream signer threshold: `1/1 service account`
- Hash ID: `0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929`

## DEPOSIT_ROLE

- Holder: `Deposit Service Wallet`
- Upstream signer threshold: `1/1 service account`
- Hash ID: `0x2561bf26f818282a3be40719542054d2173eb0d38539e8a8d3cff22f29fd2384`

# Operations

本章只说明 Safe 网页端如何填写和复核交易。默认使用 `Multisig Calldata Checker` 生成和校验 calldata，不要求操作者安装命令行工具。

- Tool URL: `https://web-three-mauve-40.vercel.app`

## Arbitrum One Target 地址

- Vault Proxy: `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Admin Timelock: `ops/config/set-roles.json` 的 `chains.arb1.roles.admin.timelock`
- Governance Timelock: `ops/config/set-roles.json` 的 `chains.arb1.roles.upgrade.timelock`
- 当前 Timelock delay: `259200` 秒

注意：Timelock 地址必须以 `ops/config/set-roles.json` 中的最终值为准。如果该字段仍为 `0x0000000000000000000000000000000000000000`，说明该 Timelock 尚未完成部署或配置写回，不能发起对应操作。

## Direct 操作如何填写 Safe

适用操作：`grantRole`、`revokeRole`、`addToken`、`updateToken`、`addValidators`、`updateValidatorRequiredPower`、`removeValidators`、`toggle`。

1. 打开 `Multisig Calldata Checker`，选择目标链和操作。
2. 选择 `Encode`，按审批单填写参数。
3. 复制工具展示的 `ABI JSON`。
4. 打开 Safe `Transaction Builder`。
5. `To` 填 `Vault Proxy`：`0xAB3D96237328385f8988166c6d7788a63f48dDa6`。
6. 粘贴对应操作的 `ABI JSON`，选择同名函数。
7. 在 Safe 中填写和 checker 完全相同的参数。
8. 进入 Safe `Review` 页面，复制 Safe 展示的 `Data`。
9. 回到 checker，切换 `Decode`，粘贴 Safe `Data`，确认函数名、target、参数全部一致。
10. 只有 checker `Encode`、Safe 参数、Safe `Data`、checker `Decode` 四者一致，才进入签名。

## Timelock 操作如何填写 Safe

适用操作：`updatePendingWithdrawChallengePeriod`、`setRebalanceReceiver`、`withdrawFees`、`upgradeToAndCall`。

Timelock 操作有两层 calldata：

- Inner calldata: Vault Proxy 上真正要执行的业务函数。
- Outer calldata: TimelockController 的 `schedule` 或 `execute`。

### 生成 inner calldata

1. 打开 checker，选择目标链和业务操作。
2. 选择 `Encode`，按审批单填写业务参数。
3. 确认 checker 展示的 inner target 是 `Vault Proxy`：`0xAB3D96237328385f8988166c6d7788a63f48dDa6`。
4. 复制生成出的 inner calldata。
5. 用 checker 的 `Decode` 模式粘贴 inner calldata，确认业务函数和参数正确。

### 发起 schedule

1. 在 checker 中继续生成 Timelock `schedule` calldata。
2. Timelock target 按操作类型填写：
   - `ADMIN_ROLE` 操作的 Safe `To` 填 Admin Timelock。
   - `UPGRADE_ROLE` 操作的 Safe `To` 填 Governance Timelock。
3. Safe `ABI JSON` 粘贴 `schedule` ABI。
4. Safe 函数选择 `schedule(address,uint256,bytes,bytes32,bytes32,uint256)`。
5. Safe 参数填写：
   - `target`: `Vault Proxy`
   - `value`: `0`
   - `data`: inner calldata
   - `predecessor`: 无前置依赖时填 `0x0000000000000000000000000000000000000000000000000000000000000000`
   - `salt`: Lark 审批记录里的 `bytes32` salt
   - `delay`: `259200`
6. Safe `Review` 页面复制 `Data`，用 checker `Decode` 解出 outer calldata。
7. 核对 outer `target` 是 Vault Proxy，outer `data` 完全等于 inner calldata，`salt` 和 `delay` 与审批记录一致。

### 发起 execute

1. 等 Timelock delay 到期后，在 checker 中生成 Timelock `execute` calldata。
2. Safe `To` 仍然填对应 Timelock，不要填 Vault Proxy。
3. Safe `ABI JSON` 粘贴 `execute` ABI。
4. Safe 函数选择 `execute(address,uint256,bytes,bytes32,bytes32)`。
5. Safe 参数填写：
   - `target`: 与 `schedule.target` 完全一致
   - `value`: 与 `schedule.value` 完全一致
   - `data`: 与 `schedule.data` 完全一致
   - `predecessor`: 与 `schedule.predecessor` 完全一致
   - `salt`: 与 `schedule.salt` 完全一致
6. Safe `Review` 页面复制 `Data`，用 checker `Decode` 解出 outer 和 inner calldata。
7. 只有 outer 参数与 schedule 完全一致，且 inner 业务参数仍然正确，才进入签名。

## 操作清单和 ABI JSON

### `grantRole(bytes32,address)`

- Role: `DEFAULT_ADMIN_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `role`: 使用 checker 下拉选择，不要手输 role hash。
  - `account`: 被授予角色的地址。
- ABI JSON:

```json
[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"grantRole","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `revokeRole(bytes32,address)`

- Role: `DEFAULT_ADMIN_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `role`: 使用 checker 下拉选择，不要手输 role hash。
  - `account`: 被回收角色的地址。
- ABI JSON:

```json
[{"inputs":[{"internalType":"bytes32","name":"role","type":"bytes32"},{"internalType":"address","name":"account","type":"address"}],"name":"revokeRole","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `upgradeToAndCall(address,bytes)`

- Role: `UPGRADE_ROLE`
- Path: Governance Timelock
- Inner target: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Safe `To`: Governance Timelock
- 参数：
  - `newImplementation`: 新 implementation 地址。
  - `data`: 升级后需要执行的迁移或初始化 calldata；没有则填 `0x`。
- ABI JSON:

```json
[{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"}]
```

### `updatePendingWithdrawChallengePeriod(uint256)`

- Role: `ADMIN_ROLE`
- Path: Admin Timelock
- Inner target: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Safe `To`: Admin Timelock
- 参数：
  - `newValue`: 新挑战期秒数。
- ABI JSON:

```json
[{"inputs":[{"internalType":"uint256","name":"newValue","type":"uint256"}],"name":"updatePendingWithdrawChallengePeriod","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `setRebalanceReceiver(address)`

- Role: `ADMIN_ROLE`
- Path: Admin Timelock
- Inner target: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Safe `To`: Admin Timelock
- 参数：
  - `newReceiver`: `rebalanceWithdraw` 固定收款地址。
- ABI JSON:

```json
[{"inputs":[{"internalType":"address","name":"newReceiver","type":"address"}],"name":"setRebalanceReceiver","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `withdrawFees(address[],address)`

- Role: `ADMIN_ROLE`
- Path: Admin Timelock
- Inner target: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- Safe `To`: Admin Timelock
- 参数：
  - `tokens`: 要提取手续费的 token 地址列表；原生币使用 `0x0000000000000000000000000000000000000000`。
  - `to`: 手续费收款地址。
- ABI JSON:

```json
[{"inputs":[{"internalType":"address[]","name":"tokens","type":"address[]"},{"internalType":"address","name":"to","type":"address"}],"name":"withdrawFees","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `addToken(address,uint256,uint256)`

- Role: `TOKEN_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `token`: token 地址。
  - `hardCapRatioBps`: 快提硬上限比例，单位 bps。
  - `refillRateMps`: 快提额度回补速度，单位 mps。
- ABI JSON:

```json
[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"hardCapRatioBps","type":"uint256"},{"internalType":"uint256","name":"refillRateMps","type":"uint256"}],"name":"addToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `updateToken(address,uint256,uint256)`

- Role: `TOKEN_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `token`: token 地址。
  - `hardCapRatioBps`: 新快提硬上限比例，单位 bps。
  - `refillRateMps`: 新快提额度回补速度，单位 mps。
- ABI JSON:

```json
[{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"hardCapRatioBps","type":"uint256"},{"internalType":"uint256","name":"refillRateMps","type":"uint256"}],"name":"updateToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `addValidators((address,uint256)[],uint256)`

- Role: `VALIDATOR_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `validators`: validator 列表，每项包含 `signer` 和 `power`。
  - `requiredPower`: 该 validator 集合通过校验所需最小 power。
- ABI JSON:

```json
[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"},{"internalType":"uint256","name":"requiredPower","type":"uint256"}],"name":"addValidators","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `updateValidatorRequiredPower((address,uint256)[],uint256)`

- Role: `VALIDATOR_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `validators`: 已存在的 validator 集合，必须与链上集合一致。
  - `newRequiredPower`: 新的最小 required power。
- ABI JSON:

```json
[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"},{"internalType":"uint256","name":"newRequiredPower","type":"uint256"}],"name":"updateValidatorRequiredPower","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `removeValidators((address,uint256)[])`

- Role: `VALIDATOR_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `validators`: 要删除的 validator 集合。
- ABI JSON:

```json
[{"inputs":[{"components":[{"internalType":"address","name":"signer","type":"address"},{"internalType":"uint256","name":"power","type":"uint256"}],"internalType":"struct ValidatorInfo[]","name":"validators","type":"tuple[]"}],"name":"removeValidators","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `toggle(bool)`

- Role: `PAUSE_ROLE`
- Path: Direct
- Safe `To`: Vault Proxy `0xAB3D96237328385f8988166c6d7788a63f48dDa6`
- 参数：
  - `pause`: `true` 表示暂停，`false` 表示恢复。
- ABI JSON:

```json
[{"inputs":[{"internalType":"bool","name":"pause","type":"bool"}],"name":"toggle","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

## TimelockController ABI JSON

### `schedule(address,uint256,bytes,bytes32,bytes32,uint256)`

```json
[{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"bytes32","name":"predecessor","type":"bytes32"},{"internalType":"bytes32","name":"salt","type":"bytes32"},{"internalType":"uint256","name":"delay","type":"uint256"}],"name":"schedule","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

### `execute(address,uint256,bytes,bytes32,bytes32)`

```json
[{"inputs":[{"internalType":"address","name":"target","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"bytes","name":"data","type":"bytes"},{"internalType":"bytes32","name":"predecessor","type":"bytes32"},{"internalType":"bytes32","name":"salt","type":"bytes32"}],"name":"execute","outputs":[],"stateMutability":"payable","type":"function"}]
```

## 支持的操作

### grantRole

- Required Role: `DEFAULT_ADMIN_ROLE`
- Path: `Governance Safe -> Vault Proxy`
- Parameters:
  - `role`: 要授予的角色 hash
  - `account`: 接收该角色的地址
- 复核重点：
  - `role` 不能选错
  - `account` 必须与审批记录一致

### revokeRole

- Required Role: `DEFAULT_ADMIN_ROLE`
- Path: `Governance Safe -> Vault Proxy`
- Parameters:
  - `role`: 要回收的角色 hash
  - `account`: 要失去该角色的地址
- 复核重点：
  - 不要误回收仍在使用中的 signer / service account

### upgradeToAndCall

- Required Role: `UPGRADE_ROLE`
- Path: `Governance Safe -> Governance Timelock -> Vault Proxy`
- Parameters:
  - `newImplementation`: 新 implementation 地址
  - `data`: 升级后要附带执行的初始化或迁移 calldata；没有就填 `0x`
- 复核重点：
  - `newImplementation` 必须是经过审计和审批的正式实现
  - `data` 必须明确知道含义，不能默认视为安全
  - `schedule` 和 `execute` 的 outer calldata 必须与同一个 inner calldata 对应

### updatePendingWithdrawChallengePeriod

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Admin Timelock -> Vault Proxy`
- Parameters:
  - `newValue`: 新 challenge period 秒数

### setRebalanceReceiver

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Admin Timelock -> Vault Proxy`
- Parameters:
  - `newReceiver`: 新的 rebalance 收款地址
- 复核重点：
  - `newReceiver` 必须来自内部地址台账

### withdrawFees

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Admin Timelock -> Vault Proxy`
- Parameters:
  - `tokens`: 要提取手续费的 token 地址数组，原生币用 `address(0)`
  - `to`: 手续费接收地址
- 复核重点：
  - `to` 必须是已批准的 treasury 或指定接收地址

### addToken

- Required Role: `TOKEN_ROLE`
- Path: `Token Safe -> Vault Proxy`
- Parameters:
  - `token`: 新增 token 地址，原生币用 `address(0)`
  - `hardCapRatioBps`: 快提额度比例
  - `refillRateMps`: 回补速率
- 复核重点：
  - `token` 链、地址、decimals、币种归属都必须核对

### updateToken

- Required Role: `TOKEN_ROLE`
- Path: `Token Safe -> Vault Proxy`
- Parameters:
  - `token`: 已支持的 token 地址
  - `hardCapRatioBps`: 新的快提额度比例
  - `refillRateMps`: 新的回补速率

### addValidators

- Required Role: `VALIDATOR_ROLE`
- Path: `Validator Safe -> Vault Proxy`
- Parameters:
  - `validators`: validator 数组，元素包含 `signer` 和 `power`
  - `requiredPower`: 通过门槛
- 复核重点：
  - `validators` 顺序必须正确
  - `power` 和 `requiredPower` 不能填错

### updateValidatorRequiredPower

- Required Role: `VALIDATOR_ROLE`
- Path: `Validator Safe -> Vault Proxy`
- Parameters:
  - `validators`: 必须与链上现有集合完全一致
  - `newRequiredPower`: 新门槛

### removeValidators

- Required Role: `VALIDATOR_ROLE`
- Path: `Validator Safe -> Vault Proxy`
- Parameters:
  - `validators`: 要删除的原集合，必须与链上完全一致
- 复核重点：
  - 删除前必须确认新 validator 集合已经生效
  - 删除前必须确认签名服务已经切到新集合

### toggle

- Required Role: `PAUSE_ROLE`
- Path: `Emergency Guardian Safe -> Vault Proxy`
- Parameters:
  - `pause`: `true` 表示暂停，`false` 表示恢复
