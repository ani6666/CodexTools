# CodexTools

CodexTools 是面向个人开发者的本地 Codex 管理工具，聚焦运行身份切换、环境诊断和 Skills 管理。

## 项目状态

项目目前处于早期开发阶段，安装与使用说明将在首个可用版本发布时补充。

当前里程碑为 M1 Codex 格式与路径预研。研究使用 PowerShell 7/.NET 零依赖探针和脱敏固定样本，暂不引入正式 Tauri/React 应用。

## 核心方向

- 管理并可靠切换 Codex 运行身份；
- 诊断本地配置、认证和实际生效状态；
- 管理本地 Skills；
- 坚持本地优先，不依赖云端账号或远程遥测。

可公开的样本证据等级和脱敏边界见 [M1 固定样本](tests/fixtures/README.md)，单独测试入口为：

```powershell
pwsh -NoProfile -File .\tests\CodexFormatResearch.Tests.ps1
```
