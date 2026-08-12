# CodexTools

CodexTools 是面向个人开发者的本地 Codex 管理工具，聚焦运行身份切换、环境诊断和 Skills 管理。

## 项目状态

项目目前处于早期开发阶段，安装与使用说明将在首个可用版本发布时补充。

M1 Codex 格式与路径预研已经用 PowerShell 7/.NET 零依赖探针和脱敏固定样本固化。M2.5 在 M2.2-M2.4 核心之上增加无正式 UI 的 Rust 两阶段纵向入口：`preview_from_store` 在短 owner 内生成不含正文的 approved intent并在返回前释放锁，调用方确认后由 `execute_approved` 重新取得 owner、重新读取 CurrentUser DPAPI 与 metadata、逐字段重算一致后才切换。切换事务的 auth 恢复快照同样使用绑定 root/transaction/source 证据的 CurrentUser-DPAPI envelope；普通切换与回滚的 config/auth 临时文件共用 schema v10 持久 owner 和 Windows 持续句柄原语：首个字节前记录 owner，root namespace 由无 delete-share 的目录句柄钉住，文件以 VolumeSerial/FileId128 绑定；初始 `CreateFileW` 原子携带 `FILE_FLAG_DELETE_ON_CLOSE`，durable identity 后通过同句柄和固定 root handle 的相对 hard-link 交接到规范 temp，再由同一句柄写入、校验、相对 rename 或 disposition cleanup。schema v10 是首个受支持生产格式；pre-v10/v1 内部草稿只做脱敏只读诊断并 fail closed，不自动解析、迁移或删除。short write、flush、sync、重读、rename 不确定结果与 readonly destination 均可重开收敛，未知 identity/reparse 原样保留并阻断。committed/rolled_back 后通过可重开 cleanup intent 清除全部事务材料。A/B 连续 100 次均执行 prewrite preview→批准执行→原路径重读，DPAPI 前向读取共 200 次，逐轮终态事务目录为零，随后恢复初始联合状态。正式 Tauri/React 应用、真实浏览器登录和网络请求仍未引入。

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
pwsh -NoProfile -File .\tests\M20Workspace.Tests.ps1
pwsh -NoProfile -File .\tests\M21IdentityCore.Tests.ps1
pwsh -NoProfile -File .\tests\M22CodexAdapter.Tests.ps1
pwsh -NoProfile -File .\tests\M23SwitchTransaction.Tests.ps1
pwsh -NoProfile -File .\tests\M24CredentialBackup.Tests.ps1
pwsh -NoProfile -File .\tests\M25VerticalClosure.Tests.ps1
```

本地协作工作树可能提供 `scripts/verify-repo.ps1` 统一入口；`scripts/` 属于 Git 忽略的本地协作资料，公开克隆不保证包含该脚本，因此不作为公开验证入口。
