# Android Integrity Probe

基于 **Jetpack Compose + Material 3** 的 Android 完整性与密钥调试工具。支持浅色 / 深色主题，检测和密钥操作在后台线程执行，旋转屏幕保留当前会话结果。

## 四个工作区

### 设备检测

以状态卡片展示以下 12 项本机探测结果，并汇总 PASS / PARTIAL / FAIL 数量：

1. StrongBox 私钥签名
2. StrongBox Key Attestation 证书链
3. TEE / KeyMint / Keymaster 私钥签名
4. TEE / KeyMint / Keymaster Key Attestation 证书链
5. Android Key Attestation 的 verifiedBootState / deviceLocked 等字段
6. 厂商完整性服务
7. Play Integrity API
8. 运营商网关认证
9. SIM / eSIM / SE 私钥签名
10. eSE / Secure Element 私钥签名
11. FIDO2 / Passkey / 硬件安全密钥
12. 硬件 Keystore 的 mTLS 准备能力

**PASS** 表示本地操作完成或取得材料，并不表示服务端已经验证可信；**PARTIAL** 表示仅发现能力或缺少 SDK、权限、服务端配置；**FAIL** 表示不支持或操作失败。

Play Integrity、厂商、运营商、FIDO2 等仍需各自的 SDK、后台配置和服务端验证，本工具不会伪造这些服务的 verdict。mTLS 检查不等于已完成远端 TLS 握手。

### 接口签名：荣耀 Provider 尝试版（默认页面）

针对国行荣耀 400 / Android 15 的**实验性兼容探测**。Provider FQCN 依据用户提供的 HnMMS APK 分析修正，普通 App 的完整调用能力仍需实测。不需要读取目标 App 的私钥，也不尝试访问其他 App 的命名空间。

固定调用路径：

```text
列出 Provider
→ 如未注册，反射 com.hihonor.android.security.keystore.HwUniversalKeyStoreProvider.install()
→ 按完整实现类名找到注册后的 Provider 实例（不猜测 JCA 名称）
→ KeyStore.getInstance("HwKeystore")，检查实际选中的是同一个 Provider
→ 密钥生成和签名显式使用该 Provider 实例
→ 指定 alias 不存在时生成 EC P-256 密钥并请求证明，存在则复用
→ 获取同一 alias 的证书链和私钥操作句柄
→ SHA256withECDSA 对用户输入的 UTF-8 原文字节签名
→ 使用叶证书公钥本地验签
```

- **仅探测 Provider 与接口**：不生成密钥，只检查接口能否注册、打开。探测成功不等于证明能力或签名能力已确认。
- **自定义 alias**：操作本 App 可访问的条目；不会因为 alias 与目标 App 相同就取得其密钥。创建后持久保留，不在签名结束后自动删除。重复运行复用旧条目。
- **自定义生成时的证明挑战**：按 UTF-8 文本输入，1–128 字节。`challenge_intelligent` 只是预填文本，不假设它一定是目标协议的实际值。修改输入不会改变已有证书的 challenge；需要新 alias，或确认删除后重建。
- **自定义签名内容**：任意 UTF-8 文本，包括空文本；保留空格、换行与分隔符，不 trim、不归一化、不预先哈希。界面最多接收 16384 个 UTF-16 单元，底层限制 65536 字节。协议示例为三个请求头的实际值 `appPkg|originUdid|requestNonce`，输入的内容就是签名内容。
- **签名输出**：`SHA256withECDSA`，ASN.1 DER 格式；提供标准 Base64（有填充、无换行）和 Hex。不是 Base64URL，也不是固定 64 字节的 `r||s`。仅本地验签通过后展示 `sign`。
- **证书输出**：原始返回顺序的完整 PEM、每张证书 PEM、Base64 DER JSON 数组、公钥 PEM、每级证书及 SPKI 的 SHA-256 指纹、Subject / Issuer / 扩展 OID。JSON 数组不是已确认的目标 `cerChain` 字段封装，需对照实际协议。
- **失败可诊断**：保留阶段、完整异常及 cause 链；若已经读取到证书而签名失败，仍可复制证书。类缺失、隐藏 API 限制、参数不兼容、权限拒绝都作为失败报告，不自动切换到 `AndroidKeyStore`、软件密钥或本地 CA。
- **删除需确认**：只删除界面确认的 alias；不可恢复。清除显示结果不删除密钥，也不清空剪贴板。
- **复制**：输入原文、本次操作原文快照、字节详情、Base64 / Hex 签名、各证书与完整报告均有复制入口，也可选中文本。报告可能含设备/应用标识与请求内容，分享前请检查。
- 表单与结果仅在 ViewModel 会话内保留，旋转和切页不丢失；不保存请求文本到文件或 SavedState。Keystore 密钥则独立持久保留。

实现只反射 `install()`，随后使用标准 `KeyGenParameterSpec`。参数转换的参考是公开的 P40 / HarmonyOS 2.0 实现；荣耀版是否接受这些参数仍需实测。不绕过隐藏 API，不猜测替换成其他厂商类名，不导出私钥。该路径没有请求 StrongBox，也不凭接口名称声称密钥一定在安全硬件里。

标准 Android Attestation OID 的 challenge 会尽可能解析；未知厂商 OID 不套用 Android ASN.1 schema。链尾只标为返回链尾，不自动成为可信根。本地解析与验签不等于服务端信任链、撤销状态或应用身份检查通过。不会发送 HTTP 请求。

### 软件实验：App 生成 → 导入 Keystore

1. 选择 **EC P-256** 或 **RSA 2048**。
2. 自定义证书 Common Name（1–64 个可见字符）与有效期（1–3650 天）。
3. 选择默认 **Android Keystore** 或显式 **请求 StrongBox**。
4. 点击“随机生成并导入”。

每次使用 `SecureRandom` 生成新密钥、32 字节 challenge、证书序列号和独立的本地调试 CA。界面展示：

- **PKCS#8 私钥 PEM**：App 内生成的原始私钥，可以显示、复制。
- **SubjectPublicKeyInfo 公钥 PEM**。
- **匹配的 X.509 调试证书链 PEM**：叶证书 → 本地自签 CA（两张）。
- 证书 Subject / Issuer / Serial / 有效期 / SHA-256 指纹。
- 软件签名与叶证书公钥验签结果。
- Keystore 导入结果、KeyInfo origin、实际安全级别。
- 从 Keystore 读回的证书链一致性检查、使用导入私钥签名并以证书公钥验签的结果。

默认 Keystore 不保证落在 TEE；界面报告 `KeyInfo` 的实际值。API 31+ 可区分 Software / TEE / StrongBox；更早版本报告 `insideSecureHardware`，不能据此区分 TEE 和 StrongBox。本项目使用的 StrongBox 导入公开 API 需要 Android 12 / API 31+（硬件内新生成 StrongBox 密钥的 API 则从 28 开始），也取决于设备、算法和系统实现；失败时不会自动降级或重试到其他目标，已生成的材料仍会显示。

**这里的导入是临时调试验证**：完成检查后删除临时 Keystore 条目，不作为持久化密钥管理器。清理失败会显示 alias 和错误。

> 导入后，Keystore 句柄的私钥不可导出，但导入前的软件副本仍可显示。这不具备“私钥从未离开安全硬件”的保证。导入链是 App 本地签发的调试链，不是 Android Key Attestation，不受 Google、系统或任何生产 CA 信任。本地 CA 私钥不导出。

### 硬件证书

独立在 Android Keystore 内生成新的密钥，分别请求默认路径和 StrongBox Attestation，显示完整证书详情、证明字段和 PEM。此路径的私钥从生成开始就不可导出，与“软件实验”页面的软件生成/导入路径完全分离，也不会替代“接口签名”的厂商路径。

每次操作使用新的本地随机 challenge，临时密钥在读取材料后清理。本地随机 challenge 不是服务端 challenge，也不能代替服务端的新鲜性校验。

## 复制与私钥保护

- 报告、结果详情和 PEM 支持长按选中文本。
- 支持复制单项检测、完整检测报告、私钥、公钥、证书链、签名结果与完整调试材料；按钮复制的是完整原文，不是屏幕上可见的部分。
- 通过按钮复制私钥或含私钥的完整材料前会弹出确认；设置剪贴板敏感标记（Android 13+ 隐藏系统剪贴板预览）。系统选区复制不经过自定义确认框。
- 生成的密钥材料不写入日志、文件、SavedState 或备份，仅保留在会话内存中；旋转屏幕不会重新生成，进程结束后不恢复。
- 有调试密钥或操作正在进行时启用 `FLAG_SECURE`，阻止截图及最近任务预览泄露。
- “清除调试材料”释放当前结果引用，不保证 JVM 内存立即擦除，也**不会清除系统剪贴板**。调试结束后请手动清理剪贴板；其他应用或设备同步功能可能读取已复制的私钥。不要使用生产密钥。

## 安全边界

本 App 不是完整反模拟 / 反 unidbg 方案。真正有意义的完整性校验必须同时具备：

- 服务端随机 nonce / challenge 与新鲜性校验；
- 服务端验签；
- 服务端验证证书链 / 签名链、可信根及相关证明字段。

本机显示的安全级别和签名结果只是调试信息，不能单独作为不可伪造的证明。

## 构建与测试

要求 JDK 17、Gradle 8.9、Android SDK Platform 35 / Build Tools 35.0.0；最低支持 Android 6 / API 23。本仓库未包含 Gradle Wrapper，请使用本地 Gradle 或 GitHub Actions：

```bash
gradle testDebugUnitTest testReleaseUnitTest lintDebug lintRelease assembleDebug assembleRelease --no-daemon
```

APK：

- **推荐测试包**：`app/build/outputs/apk/release/app-release.apk`。启用 R8 代码优化/移除无用代码和资源压缩，非 debuggable；仍使用开发测试签名，不是生产发布版。Actions artifact：`android-integrity-probe-trial-apk`。
- **未压缩对照包**：`app/build/outputs/apk/debug/app-debug.apk`。Actions artifact：`android-integrity-probe-debug-apk`。

Actions 同时运行两种构建的单元测试和 Lint、验证优化包签名，并在构建摘要记录 APK 与 DEX 实际体积。R8 mapping 随测试报告上传，不靠禁用检查或全库 keep 规则来构建。

注意：GitHub Runner 的临时 debug 签名在不同构建之间可能不同。若覆盖安装提示签名不一致，需要先卸载旧测试版再安装（会清除本 App 的数据和 Keystore 密钥，请先复制所需报告）。不通过关闭包签名验证解决此问题。

单元测试覆盖 EC/RSA 私钥和公钥 PEM 回读、证书链签名、密钥与叶证书匹配、随机性及输入校验；接口签名另有字节编码、创建/复用、无降级、失败保留证书、错误签名抑制及删除范围等测试。连接设备或模拟器后运行：

```bash
gradle connectedDebugAndroidTest
```

仪器测试覆盖多行内容完整复制、剪贴板敏感标记、EC 导入验签与临时条目清理、StrongBox 成功/不支持路径，以及厂商签名表单的原文保留、删除确认、签名/完整报告复制。不支持硬件的模拟器不能替代真机 TEE / StrongBox 验证。

### 建议人工回归

**荣耀 400 尝试版优先检查：**

1. 打开“接口签名”，运行“仅探测 Provider 与接口”，复制诊断报告；若失败，确认准确失败阶段，不视为手机不支持所有硬件 Keystore。
2. 使用新的 alias、正确的生成时 challenge 和请求原文执行签名。比对 Base64 签名、叶证书公钥、完整证书链。
3. 修改原文再次签名，确认复用同一证书、公钥；修改 challenge 也不应自动重建旧密钥。
4. 取消删除应无副作用；确认删除后再次签名才生成新的密钥和证书。
5. 在不包含厂商类的普通模拟器上确认失败报告可复制且不崩溃；在荣耀真机上确认成功或实际拒绝原因。


- 在 API 23 / 28 / 31+ 设备上运行 12 项检测及硬件证书页面，检查不支持项不会导致页面崩溃。
- 分别生成 EC、RSA；尝试默认 Keystore 和 StrongBox，确认实际存储级别、错误提示及无静默降级。
- 切换页面、旋转屏幕、连续点击运行，确认配置/结果保留且操作不并发。
- 长按选择 PEM、复制整个长报告、取消/确认私钥复制、清除后重新生成。
- 测试深色模式、较大字体、键盘输入和长证书文本滚动。

复制的 PEM 可分别保存为 `private.pem`、`public.pem`、`chain.pem`，再用 OpenSSL 检查：

```bash
openssl pkey -in private.pem -pubout -out derived-public.pem
diff public.pem derived-public.pem
openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -text -noout
# 将 chain.pem 的第二张证书单独保存为 root.pem、第一张保存为 leaf.pem：
openssl verify -CAfile root.pem leaf.pem
```

依赖 AndroidX Compose / Lifecycle / Coroutines。界面仅打包 10 个本地矢量图标，不引入完整的 material-icons-extended 图标库。Bouncy Castle 只用于直接调用的证书/ASN.1 辅助代码；软件实验的密钥生成和签名使用平台 JCA，不实例化庞大的 BC 反射算法注册表，不替换 Android 系统 Provider。荣耀签名始终显式使用实际加载的荣耀 Provider。
