# Android Integrity Probe

一个极简 Android App，用来在真机上探测设备是否具备若干“必须由服务端 challenge + 服务端验签/验链才有意义”的硬件/生态完整性能力。

## 能检测什么

App 会列出以下 12 项的本机探测结果：

1. StrongBox 私钥签名
2. StrongBox Key Attestation 证书链
3. TEE / KeyMint / Keymaster 私钥签名
4. TEE / KeyMint / Keymaster Key Attestation 证书链
5. Android Key Attestation 里的 verifiedBootState / deviceLocked 等硬件证明字段
6. 厂商安全服务的服务端签名 verdict（华为/荣耀/小米/OPPO/vivo 等 integrity token）
7. Play Integrity API 的 Google 签名 JWS
8. 运营商网关认证返回的运营商签名 token
9. SIM / eSIM / SE 内私钥签名
10. eSE / Secure Element 私钥签名
11. FIDO2 / Passkey / 硬件安全密钥签名
12. 硬件 Keystore 私钥参与的 mTLS 客户端证书握手

## 重要限制

本 App **不是** 完整反模拟/反 unidbg 方案，只是能力探测工具。

真正意义上“unidbg 无法伪造”的前提必须同时满足：

- 服务端随机 nonce/challenge
- 服务端验签
- 服务端验证证书链/签名链

不满足以上三点，本地结果只能作为调试参考。

## 结果含义

- `PASS`：本机已完成对应本地密码学操作或拿到证明材料；仍需服务端验证后才可作为可信信号。
- `PARTIAL`：只能检测到硬件/系统能力，或缺少服务端、厂商 SDK、权限、业务配置。
- `FAIL`：当前设备/系统/API 不支持，或本地操作失败。


## 证书链查看

App 内有“查看证书链”按钮，会生成新的 TEE/StrongBox attestation key，并显示：

- 证书链长度
- Android Key Attestation 解析摘要
- 每张证书的 Subject / Issuer / Serial / 有效期 / 签名算法 / 公钥算法
- SHA-256 fingerprint
- Leaf 证书是否包含 Android Key Attestation OID
- 完整 PEM 格式证书链，方便复制到服务端或 `openssl` 调试

注意：按钮里使用的是本机 demo challenge。生产环境必须使用服务端随机 nonce/challenge，并在服务端验证证书链和签名。

## 构建

GitHub Actions 会自动编译 Debug APK：

```bash
./gradlew assembleDebug
```

产物路径：

```text
app/build/outputs/apk/debug/app-debug.apk
```

## 关于 Play Integrity / 厂商 / 运营商 / FIDO2

这些能力通常不能仅靠一个离线 Demo 完成最终 verdict：

- Play Integrity 需要 Google Play services、Google Cloud/Play Console 配置、Play Integrity SDK，并由服务端验证 Google 签名 JWS。
- 厂商完整性服务需要分别接入厂商 SDK/后台配置。
- 运营商网关认证通常需要移动数据网络、运营商 SDK/API、服务端参与。
- FIDO2/Passkey 需要 WebAuthn/Credential Manager/FIDO2 API 流程，服务端验证 assertion/attestation。

本项目先保持零三方依赖，便于快速编译和真机初筛。
