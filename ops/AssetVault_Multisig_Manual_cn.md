# AssetVault 生产操作手册（中文草案）

本文档面向生产环境操作者、签名人和审核人，覆盖：

- `AssetVault` 的权限治理结构
- 各角色可执行函数及其实际含义
- 生产操作前的安全检查
- Safe 网页端的填写方式
- Lark 审批流程要求

除 `UPGRADE_ROLE` 外，其余高权限操作均为 Safe 直连 `Vault Proxy`。

# 治理结构

当前建议的治理拆分如下：

- `Governance Safe (4/7)` -> `Governance Timelock (72h)` -> `UPGRADE_ROLE`
- `Governance Safe (4/7)` -> `DEFAULT_ADMIN_ROLE`
- `Admin Safe (4/7)` -> `ADMIN_ROLE`
- `Token Safe (4/7)` -> `TOKEN_ROLE`
- `Validator Safe (4/7)` -> `VALIDATOR_ROLE`
- `Emergency Guardian Safe (3/5)` -> `PAUSE_ROLE`
- `Operator KMS` -> `OPERATOR_ROLE`
- `Deposit Service Wallet` -> `DEPOSIT_ROLE`

关键说明：

- 只有 `UPGRADE_ROLE` 负责合约升级，且必须经过 Timelock。
- `DEFAULT_ADMIN_ROLE` 不负责合约升级。
- `ADMIN_ROLE`、`TOKEN_ROLE`、`VALIDATOR_ROLE`、`PAUSE_ROLE` 都是 Safe 直连 `Vault Proxy`。
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
- 检查 `To` 地址到底是 `Vault Proxy` 还是 `Governance Timelock`，不要填反。
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
- 升级类操作应额外记录：`salt`、`schedule` 交易哈希、`execute` 交易哈希。
- Lark 审批记录应能和最终链上交易一一对应，便于回溯。

# 链上地址

## Vault Proxy

- Arbitrum One `42161`
  - Vault Proxy: `0xf105063609cbd63977d9c2bee0142c10fe3d27e8`
- Arbitrum Sepolia `421614`
  - Vault Proxy: `0xf2137a2d64ba4dafcab54959862f7384ed7be100`
- Ethereum Sepolia `11155111`
  - Vault Proxy: `0xcae91ee34ef8a1076229d9e6dbc6b1ec6248671d`

## Safe / Timelock 地址

以下地址在正式下发给运营前必须补齐：

- `Governance Safe`
- `Governance Timelock`
- `Admin Safe`
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

- Holder: `Admin Safe`
- Upstream signer threshold: `4/7`
- Hash ID: `0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775`
- Responsibilities:
  - `updatePendingWithdrawChallengePeriod(uint256)`: 修改 pending withdrawal 的挑战期长度。
  - `addRebalanceReceiver(address)`: 把地址加入 `rebalanceWithdraw` 可用的收款白名单。
  - `removeRebalanceReceiver(address)`: 把地址从 `rebalanceWithdraw` 收款白名单中移除。
  - `setRebalanceReceiver(address)`: 从白名单中选择当前生效的 `rebalanceWithdraw` 收款地址。
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

本章默认使用 `Multisig Calldata Checker` 作为操作和复核工具，不再要求操作者使用 `cast` 或其他命令行工具。

- Tool URL: `https://web-three-mauve-40.vercel.app`

## 如何使用 Multisig Calldata Checker

### Direct 型操作

1. 选择链。
2. 选择要执行的操作。
3. 在 `Encode` 模式下填写参数。
4. 工具会显示：
   - 当前应填写的 `To`
   - 当前应使用的 `ABI JSON`
   - 生成出的 calldata
5. 在 Safe `Transaction Builder` 中填入相同的 `To`、`ABI JSON` 和参数。
6. 到 `Review` 页面后，复制 Safe 生成的 `Data`。
7. 回到 checker 的 `Decode` 模式，粘贴这段 `Data`，确认解码出的函数和参数与审批单完全一致。
8. 只有在 `Encode` 结果、Safe `Review` 里的 `Data`、以及 `Decode` 结果三者一致时，才进入签名。

### Timelock 型操作

只有 `upgradeToAndCall` 经过 Timelock，必须按两层 calldata 处理。

1. 先在 checker 中选择 `upgradeToAndCall`，填写 `newImplementation` 和 `data`，生成 inner calldata。
2. 确认 inner calldata 的 `To` 是 `Vault Proxy`。
3. 再继续生成 Timelock 的 outer calldata：
   - `schedule`
   - `execute`
4. 确认 outer calldata 的 `To` 是 `Governance Timelock`，不是 `Vault Proxy`。
5. 对 `schedule` 和 `execute`，必须重点核对：
   - `target` 是否为 `Vault Proxy`
   - `data` 是否与 inner calldata 完全一致
   - `predecessor` 是否正确
   - `salt` 是否与审批记录一致
   - `delay` 是否为预期值
6. 在 Safe `Review` 页面复制 outer `Data`，回到 checker `Decode` 模式逐项解码确认。
7. `execute` 时使用的 `target / data / predecessor / salt` 必须与 `schedule` 完全一致，只是 `schedule` 多一个 `delay`。

## 通用复核原则

- 不要手填 raw calldata，应以 checker 生成结果为准。
- Safe 中实际填写的参数、checker `Encode` 结果、Safe `Review` 的 `Data`、checker `Decode` 结果，四者必须一致。
- 对于地址类参数，除了解码正确，还要核对地址用途是否和审批一致，例如 treasury、receiver、validator、implementation。
- 对于数组和 validator 集合，必须逐项核对顺序和数值，不能只看首尾几项。
- 对于升级操作，必须同时保存 inner calldata、`schedule` 交易哈希、`execute` 交易哈希和 `salt`。

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
- Path: `Admin Safe -> Vault Proxy`
- Parameters:
  - `newValue`: 新 challenge period 秒数

### setRebalanceReceiver

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Vault Proxy`
- Parameters:
  - `newReceiver`: 新的 rebalance 收款地址
- 复核重点：
  - `newReceiver` 必须已经在 rebalance receiver 白名单里
  - `newReceiver` 必须来自内部地址台账

### addRebalanceReceiver

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Vault Proxy`
- Parameters:
  - `receiver`: 要加入白名单的 rebalance 收款地址
- 复核重点：
  - 该地址加入白名单后，未来可以被设为 active rebalance receiver
  - 地址来源和用途必须与审批记录一致

### removeRebalanceReceiver

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Vault Proxy`
- Parameters:
  - `receiver`: 要从白名单移除的 rebalance 收款地址
- 复核重点：
  - 当前 active rebalance receiver 不能直接移除
  - 若要移除旧地址，应先切换到新的 active receiver，再删除旧地址

### withdrawFees

- Required Role: `ADMIN_ROLE`
- Path: `Admin Safe -> Vault Proxy`
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
