# CodexTools

CodexTools 是面向个人开发者的本地 Codex 管理工具，聚焦运行身份切换、环境诊断和 Skills 管理。

## 项目状态

项目目前处于早期开发阶段，安装与使用说明将在首个可用版本发布时补充。

M3.0 已建立桌面应用技术基线：Tauri 2.11.5、React 19.2.8、TypeScript 6.0.3 与 Vite 8.2.1。桌面壳层位于 `apps/desktop`，通过 Cargo workspace/path dependency 直接复用 M2 的 `codex-domain`、`codex-application`、`codex-adapter`、`local-infrastructure` 与 `windows-platform` crates，不复制核心逻辑。本阶段只有默认简体中文、可切换英文的静态就绪页。

### M3.1 application facade 与 typed IPC 合同

M3.1 在 `apps/desktop/src-tauri/src/application_facade` 建立纯 Rust `ApplicationFacade`，只编排 M2 已公开的错误/端口边界，不读取真实目录、凭据或网络状态。`commands.rs` 是唯一 Tauri adapter，集中注册 `describe_contract_v1` 与 `cancel_operation_v1` 两个版本化 command；`contract.rs` 的 serde DTO 使用受限 `SafeIdentifier`，复用 `codex-domain` 的高置信秘密形态检测，不接受秘密正文、路径或原始字节。`events.rs` 只定义带 `schema_version`、`operation_id`、`correlation_id` 的非敏感状态事件和可测试 `EventSink`；Accepted 事件投递失败会回滚仍处于初始可取消态的注册，使相同 operation id 可重试，若并发状态已越过回滚边界则返回 `recovery_required`。完成态提供显式释放接口，避免长生命周期 registry 无限增长。`error.rs` 将 M2 错误映射为稳定 `ErrorCode`/`ErrorEnvelope`，仅输出中文安全消息与 message key；隔离目录外写入映射为不可重试的 `compatibility_protected`。`cancellation.rs` 明确可取消检查点、M2 原子临界区的 `TooLate` 语义、重复/未知/完成后取消结果。

M3.1 不引入 `@tauri-apps/api`、前端 invoke/listen、业务 UI、扫描、身份 CRUD、网络或单实例行为。Tauri capability 仍为空权限。固定 canary、危险路径、JSON roundtrip、Debug/Display/serde 与全量 M2 错误映射由 `apps/desktop/src-tauri/tests/m31_contract.rs` 覆盖；PowerShell 合同入口为 `pwsh -NoProfile -File .\tests\M31ApplicationFacade.Tests.ps1`。

### M3.2 React shell、i18n 与设计系统

M3.2 使用 React 19 自带的 `useReducer`/Context 建立桌面应用壳，不新增生产依赖。信息架构包含概览、状态样本和偏好设置；状态样本明确标注为本地 fixture，不代表扫描、身份管理或切换流程。集中资源表提供完整 `zh-CN` 与 `en` 文案。语言偏好具有 `system`/`zh-CN`/`en` 三态：默认 `system` 动态解析 `navigator.languages` 且不写入固定语言，只有用户明确选择后才持久化；无效存储值 fail-safe 回到 system。英文缺失键回退到简体中文，未知键回显稳定 key 便于诊断。

设计系统以 CSS tokens 和复用的 Button/Card/StatusFeedback 组件覆盖颜色、排版、间距、焦点、按钮、表单、卡片及状态反馈。壳层支持正常、空、加载、错误、取消、重复操作和 `compatibility_protected` 展示；动态状态反馈固定为 `role=status`、`aria-live=polite`、`aria-atomic=true`，加载态同时使用 `aria-busy`。语言偏好存储采用窄作用域异常边界：读取失败或无效值按 system 降级并尽力清理，写入或删除失败不阻止当前会话切换，也不回显存储内容。具备语义 header/nav/aside/main、跳转主内容、键盘焦点、aria-current、全局通知 aria-live、表单标签、窄窗口、长文本、缩放溢出与 reduced-motion 基线；暗色模式使用高对比焦点 token 与双层焦点环。前端继续不使用 `@tauri-apps/api` 或 M3.1 IPC，capability permissions 保持为空。本阶段合同入口为 `pwsh -NoProfile -File .\tests\M32ReactShell.Tests.ps1`。

### M3.3 首次受控导入、身份与模型预设

M3.3 将 M2.6/M2.7 的已放行服务接入桌面生产路径。首次扫描只由“扫描本地候选”按钮显式发起，IPC 只接受 `default_codex` 受控根与 opaque identifiers；真实路径、config/auth 原文、credential material 与敏感 fingerprint context 不进入 DTO、event、DOM 或 storage。扫描通过 exact rescan 返回 secret-free 状态；导入确认进入 M3.1 不可取消临界区，并复用 M2.6 credential owner、recovery journal 与 bundle transaction。窗口挂载只刷新本地数据库中的非敏感身份摘要，不会扫描默认 Codex 根。

身份列表、刷新和 rename 使用真实 SQLite repository 与 optimistic concurrency；首个身份仍只能来自 M2.6 受控导入或已有安全 reference。模型预设列表、create-and-bind 与 update-and-bind 复用 M2.7 `PresetBindingService`，前端不会用多个 invoke 拼装原子操作。managed name/model 在 DTO 构造和 domain 服务两层拒绝高置信秘密与路径形态。前端对 stale response、重复点击、卸载、IPC reject、空/加载/验证/冲突/恢复状态均使用稳定安全消息，不显示技术错误原文。

Tauri adapter 仍集中在 `commands.rs`，所有 SQLite/DPAPI 工作通过 `spawn_blocking` 离开 UI 线程。`TauriEventSink` 仅发射阶段、计数、opaque id 与安全 summary code；Accepted 投递失败会在调用后端前回滚 operation 注册。capability 继续只绑定 `main` 窗口，并仅授予 `core:event:allow-listen` 与 `core:event:allow-unlisten`；没有 event emit、shell/fs/dialog/http/process plugin 或网络权限。监听注册失败会进入固定、本地化的事件通道不可用状态，业务 invoke 结果仍独立呈现；卸载竞态和异步 unlisten 失败不会形成卸载后状态更新或未处理拒绝。M3.3 合同入口为 `pwsh -NoProfile -File .\tests\M33DesktopIdentity.Tests.ps1`、`cargo test -p codextools-desktop --test m33_contract --all-features` 与 `npm test`。

capability 仅绑定 `main` 窗口，当前权限数组精确为事件 `listen/unlisten` 两项；后续任何 event emit、文件系统、Shell、窗口或业务命令权限都必须逐项评审。秘密正文不得进入前端、事件、日志或错误；静态门槛与 Rust canary 合同测试会阻止桌面边界建立 `CODEX_HOME`、认证文件、Token 或 Authorization 正文入口。

### M3.4 身份切换与恢复流程

M3.4 复用 M2.5 `VerticalSwitchPlanner::preview_from_store` 与 `execute_approved`：用户只能从已保存身份显式生成只读预览，后端保留绑定当前 config/auth baseline、身份/预设/credential 版本和过期时间的 `VerticalPreparedIntent`。前端批准时只回传 opaque plan id、plan version 与 operation id；执行前后均重新读取仓储与 credential owner，并逐字段重算同一意图。任何 local state、身份、预设或 credential 变化都会返回 `plan_stale`，不会静默重新规划。

执行沿用 M2.3 跨进程写锁、联合快照、原子替换、journal 与 `recover_root`。取消只在进入原子临界区前生效；进入后稳定返回 `too_late`，事务仍会完成或进入恢复。typed event 只含阶段、计数和 opaque ids；事件失败不会中断已进入临界区的事务，UI 以最终 command/query 结果收敛。重启后可用 opaque operation id 查询持久 switch transaction；pending/recovery 仅显示安全摘要，恢复必须再次明确确认且不会自动启动。

React 在既有身份与预设管理下增加 preview 摘要、明确确认、进度、取消太晚、冲突和恢复状态。中英文资源、`aria-live`、`aria-busy`、原生 `progress`、键盘和窄窗均保持；浏览器 storage 只保存 opaque pending operation id。capability 仍精确为 `core:event:allow-listen` 与 `core:event:allow-unlisten`，没有新增依赖、plugin、event emit、网络或 schema migration。合同入口为 `pwsh -NoProfile -File .\tests\M34IdentitySwitch.Tests.ps1`、`cargo test -p codextools-desktop --test m34_contract --all-features`、`cargo test -p codextools-desktop --lib m34_backend --all-features` 与 `npm test`。

### M3.0 依赖、许可证与体积评估

直接新增依赖均在锁文件中精确解析：

| 依赖 | 必要性 | 许可证 | 安装/构建体积影响 | 未采用的替代方案 |
| --- | --- | --- | --- | --- |
| `tauri` 2.11.5 / `tauri-build` 2.6.3 | 原生桌面运行时、配置与构建时代码生成 | MIT OR Apache-2.0 | Cargo 锁定包由 22 增至 430；Windows 构建会编译 WebView2/Wry 与 Tauri 传递依赖 | Electron 会捆绑 Chromium、安装与发布体积更大；Wails 需要 Go 且不能自然复用现有 Rust workspace |
| `@tauri-apps/cli` 2.11.4 | 提供 `tauri info/build/dev` 的可复现入口，仅开发依赖 | MIT OR Apache-2.0 | npm 平台 CLI 二进制是 `node_modules` 的主要部分之一，不进入前端 bundle | 全局 CLI 会产生不可复现的版本漂移 |
| `react` / `react-dom` 19.2.8 | 壳层组件与 DOM 渲染 | MIT | 本机安装内容约 7.5 MB；生产 bundle 经 Vite tree-shaking 压缩 | 原生 DOM 体积更小，但不符合已锁定 React 技术栈且会增加后续 UI 迁移成本 |
| `vite` 8.2.1 / `@vitejs/plugin-react` 6.0.5 | 开发服务器、TypeScript/JSX 转换和生产构建 | MIT | 与编译器及 CLI 合计后，本机完整 `node_modules` 约 84.1 MB；仅开发时使用 | 手写 Rollup/esbuild 配置需要更多维护且偏离技术栈要求 |
| `typescript` 6.0.3 | 严格静态类型检查 | Apache-2.0 | npm 包解压约 24.3 MB，仅开发时使用 | 7.x 是更新主版本；M3.0 选择 6.x 以降低初始 Tauri/Vite 骨架的工具链新主版本叠加风险 |
| `@types/react` / `@types/react-dom` 19.x | React 19 TypeScript 类型 | MIT | 仅开发与类型检查使用，不进入前端 bundle | 手写声明会重复上游类型且容易漂移 |
| `@tauri-apps/api` 2.11.0 | 仅提供官方 tree-shakeable `core.invoke` 与 `event.listen`，连接版本化 M3.3 commands/events | MIT OR Apache-2.0 | 新增 1 个 direct npm package；不引入原生 plugin，实际 gzip bundle 增量在验证报告中记录 | 手写 `window.__TAURI_INTERNALS__` 会依赖私有 API；通用 fs/shell/http plugins 会扩大权限且不需要 |

M3.1 仅将锁文件中已有的 `serde` 1.0.229（MIT OR Apache-2.0）提升为桌面 crate 的直接生产依赖，用于 typed IPC DTO；`serde_json` 1.0.151（MIT OR Apache-2.0）仅作为合同测试开发依赖。两者均已由 Tauri/M2 依赖图锁定，因此没有新增锁定包、没有前端 bundle 增量；替代的手写 JSON/序列化会重复成熟实现并削弱 schema/roundtrip 测试。

本机验证工具链为 Node.js 24.14.0、npm 11.12.1、Rust/Cargo 1.97.1（MSVC）。Vite 8 要求 Node.js `^20.19.0 || >=22.12.0`；Tauri 2.11.5 与 `tauri-build` 2.6.3 的 MSRV 为 Rust 1.77.2。仓库仍声明 Rust 1.85；`cargo generate-lockfile` 已按 Rust 1.85 选择兼容传递版本，未抬高现有 crates 的 MSRV。单实例只做后续评估，本阶段未添加 single-instance plugin 或行为。

M1 Codex 格式与路径预研已经用 PowerShell 7/.NET 零依赖探针和脱敏固定样本固化。M2.5 在 M2.2-M2.4 核心之上增加无正式 UI 的 Rust 两阶段纵向入口：`preview_from_store` 在短 owner 内生成不含正文的 approved intent并在返回前释放锁，调用方确认后由 `execute_approved` 重新取得 owner、重新读取 CurrentUser DPAPI 与 metadata、逐字段重算一致后才切换。切换事务的 auth 恢复快照同样使用绑定 root/transaction/source 证据的 CurrentUser-DPAPI envelope；普通切换与回滚的 config/auth 临时文件共用 schema v10 持久 owner 和 Windows 持续句柄原语：首个字节前记录 owner，root namespace 由无 delete-share 的目录句柄钉住，文件以 VolumeSerial/FileId128 绑定；初始 `CreateFileW` 原子携带 `FILE_FLAG_DELETE_ON_CLOSE`，durable identity 后通过同句柄和固定 root handle 的相对 hard-link 交接到规范 temp，再由同一句柄写入、校验、相对 rename 或 disposition cleanup。pre-v10/v1 内部草稿只做脱敏只读诊断并 fail closed，不自动解析、迁移或删除。short write、flush、sync、重读、rename 不确定结果与 readonly destination 均可重开收敛，未知 identity/reparse 原样保留并阻断。committed/rolled_back 后通过可重开 cleanup intent 清除全部事务材料。A/B 连续 100 次均执行 prewrite preview→批准执行→原路径重读，DPAPI 前向读取共 200 次，逐轮终态事务目录为零，随后恢复初始联合状态。

M2.6 在不增加桌面 command/UI 的前提下补齐 Rust-only 首次导入闭环：公开边界只接受 `ControlledRoot::DefaultCodex` 与 opaque scan id。后端通过 Windows known-folder API 解析默认根，并在同一个 pinned root 下以 no-follow、禁止写/delete share 的句柄读取 config/auth；scan id 同时绑定 root/config/auth 的 VolumeSerial、FileId128、长度与内容摘要。auth parser 只借用输入，SHA-256 流式处理且所有不可避免的 owned auth buffer 在成功、错误与 unwind 路径清零。

credential reference/material 仍由 `CredentialService` owner + recovery journal 单独拥有；同一跨进程 owner 覆盖 exact material/reference 验证、M2.6 phase 更新和带 version/kind/schema/fingerprint 条件的 bundle transaction commit，身份绑定完成后才释放。schema v11 的非秘密 `capture_import_operations` journal 解释 DPAPI 与 identity/preset/patch bundle 之间的中间态；预检后的 commit 竞态使用 exact reference、引用检查与 credential delete recovery 持久回滚，不以 best-effort 删除宣称原子。隔离测试覆盖 API-key/OAuth、schema tamper、reparse/file replacement、owner release、journal/metadata/bundle/CAS 故障、create/rotate/delete 竞争、两个 capture 进程，以及真实 `WindowsDpapiCredentialStore` helper 在五个持久切点被终止后的 reopen 收敛；helper 只使用自己的 synthetic root/material 并完成清理。M3.3 仅通过该公开服务接入桌面，不改变原子边界。

M2.7 为已有身份补齐模型预设与默认绑定的 Rust-only 原子服务。application 使用分离、带版本的 create-and-bind/update-and-bind 输入和组合 repository port；local infrastructure 在一个 SQLite `Immediate` transaction 内复读 identity/preset、执行 preset 写入与 identity CAS，再一次提交。重复的同一请求稳定返回 `AlreadyApplied`，stale version、foreign preset、唯一名冲突和并发 loser 稳定返回 `Conflict`；提交确认丢失返回 `RecoveryRequired`。受管理的 preset name/model metadata 由 domain 验证并拒绝高置信秘密与路径形态。M3.3 只增加其 desktop facade/UI adapter，没有 schema migration、网络或 credential 边界变化。

M2.8 提供 Rust-only 的显式连接探测与 OpenAI-compatible 模型候选发现核心，不增加 Tauri command、前端入口、启动联网或 schema migration。application 分离 `ProbeConnectionInput`/`DiscoverModelsInput`，用 expected identity version、credential reference 与 operation id 绑定请求；credential document 仅通过既有 `CredentialStore::read` 短借，API key 被复制到 `Zeroizing` buffer 后立即释放 store borrow，Authorization、响应原文和 endpoint 不进入公开 outcome、Debug 或错误。现有 OAuth bundle 缺少可验证 expiry，因此 M2.8 在联网前稳定返回 `compatibility_protected`，不会猜测 token 新鲜度。

网络策略默认仅允许规范化 HTTPS/443 公网端点；显式 `LoopbackDevelopment` 仅接受 localhost/127.0.0.0/8/::1。DNS 返回的全部地址逐个复核，任一 private/link-local/metadata/CGNAT/multicast/unspecified/mapped IPv6/NAT64 等地址即整体拒绝。transport 直接连接审批后的 `SocketAddr` 并保留原 host 供 HTTP Host 与 TLS SNI/证书验证，不读取代理环境、不跟随 redirect，也不提供 invalid-certificate 开关。连接、读、总时限、header/body/model count/字段长度/JSON 深度均有上限，取消在 DNS/connect/TLS/read/parse 边界收敛。唯一新增生产依赖为精确锁定的 `native-tls` 0.2.18（MIT OR Apache-2.0，默认 features 为空；Windows 使用 Schannel）；未采用 `reqwest`/`ureq`/`hyper`，避免额外运行时、代理/redirect 默认面以及无法承诺清零的高层 header 副本。合同入口为 `pwsh -NoProfile -File .\tests\M28SafeModelDiscovery.Tests.ps1` 及对应 Rust focused tests。

恢复快照终审修正后，v11 schema 期望值由 SQLite 直接执行仓库 migration 后读取，并通过 `pragma_table_xinfo`、`index_list/index_xinfo`、STRICT 状态、保留字符串/GLOB 内容的 SQL token 比较和回滚式约束行为矩阵共同审计；格式空白、注释和语句分号可等价变化，但 GLOB/string 语义篡改 fail closed。trigger 审计忽略注释与字符串字面量，只对真实跨表 INSERT/UPDATE/DELETE ledger 依赖和挂载在 ledger 上的 trigger 阻断。metadata 缺失时的破坏性 credential recovery 只有在 material reference、generation/binding、envelope hash 与解密后的 planned fingerprint 全部吻合后才删除，材料已不存在可幂等清理，替换 plaintext、stale ref/hash 或 quarantine 双重状态均保留并返回 recovery required。跨进程写锁先固定本地卷根，再使用 `NtCreateFile` 的 `RootDirectory` handle 逐组件相对、no-follow 打开；每级可由父句柄重开并核对 identity，因此同卷 DOS alias/SUBST 在逐组件间切换也不能跨越已固定父目录。任意祖先/final/lock reparse 都 fail closed，并阻止祖先与锁文件替换竞争。config 原文、TOML text/assignment value、规划输出和 `SwitchPlan` config 均使用 `Zeroizing` ownership，相关 Debug 只输出固定脱敏标记。不同受控根共享 credential 的并发 helper 只有在 repository/store 已打开并到达 owner/CAS 调用边界后才发出 barrier，测试只接受一个 Imported/AlreadyImported 与一个 Conflict，并精确核对最终 material/reference/identity/preset/patch/journal。rollback 工具嵌入 patch/manifest/entry-set trust anchor，逐组件拒绝 reparse，默认 dry-run；Apply 会先保存 durable journal 与 final backups，再做 tracked reverse 和 ignored 原子替换，失败自动补偿或保留机器可恢复状态。

## 核心方向

- 管理并可靠切换 Codex 运行身份；
- 诊断本地配置、认证和实际生效状态；
- 管理本地 Skills；
- 坚持本地优先，不依赖云端账号或远程遥测。

可公开的样本证据等级和脱敏边界见 [M1 固定样本](tests/fixtures/README.md)，单独测试入口为：

```powershell
pwsh -NoProfile -File .\tests\CodexFormatResearch.Tests.ps1
```

随公开仓库交付的 Rust 验证命令为：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace --all-targets
pwsh -NoProfile -File .\tests\M28SafeModelDiscovery.Tests.ps1
cargo test -p local-infrastructure --test m28_safe_model_discovery --all-features
pwsh -NoProfile -File .\tests\M30DesktopSkeleton.Tests.ps1
pwsh -NoProfile -File .\tests\M31ApplicationFacade.Tests.ps1
pwsh -NoProfile -File .\tests\M32ReactShell.Tests.ps1
pwsh -NoProfile -File .\tests\M33DesktopIdentity.Tests.ps1
cargo test -p codextools-desktop --test m33_contract --all-features
Push-Location .\apps\desktop
npm ci --ignore-scripts
npm test
npm run check
npm run build
npm run tauri:info
npm run tauri:build
Pop-Location
pwsh -NoProfile -File .\tests\M20Workspace.Tests.ps1
pwsh -NoProfile -File .\tests\M21IdentityCore.Tests.ps1
pwsh -NoProfile -File .\tests\M22CodexAdapter.Tests.ps1
pwsh -NoProfile -File .\tests\M23SwitchTransaction.Tests.ps1
pwsh -NoProfile -File .\tests\M24CredentialBackup.Tests.ps1
pwsh -NoProfile -File .\tests\M25VerticalClosure.Tests.ps1
pwsh -NoProfile -File .\tests\M26CredentialCaptureImport.Tests.ps1
pwsh -NoProfile -File .\tests\M27PresetBinding.Tests.ps1
```

本地协作工作树可能提供 `scripts/verify-repo.ps1` 统一入口；`scripts/` 属于 Git 忽略的本地协作资料，公开克隆不保证包含该脚本，因此不作为公开验证入口。
