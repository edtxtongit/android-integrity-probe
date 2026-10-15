package com.example.integrityprobe;

import android.content.ContextWrapper;
import android.content.Context;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.telephony.TelephonyManager;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.KeyManagerFactory;

public final class IntegrityProbe extends ContextWrapper {
    private static final String ANDROID_KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private final byte[] demoChallenge = new byte[32];
    private final List<String> temporaryAliases = new ArrayList<>();

    public IntegrityProbe(Context context) {
        super(context.getApplicationContext());
        new java.security.SecureRandom().nextBytes(demoChallenge);
    }

    public ProbeReport runProbe() {
        try {
            return collectProbe();
        } finally {
            cleanup();
        }
    }

    private ProbeReport collectProbe() {
        StringBuilder sb = new StringBuilder();
        addHeader(sb);
        List<Result> results = new ArrayList<>();

        results.add(checkStrongBoxSigning());
        results.add(checkStrongBoxAttestation());
        results.add(checkTeeSigning());
        results.add(checkTeeAttestation());
        results.add(checkVerifiedBootFields());
        results.add(checkVendorIntegrityServices());
        results.add(checkPlayIntegrity());
        results.add(checkCarrierGateway());
        results.add(checkSimEsimSePrivateKey());
        results.add(checkEseSecureElement());
        results.add(checkFido2Passkey());
        results.add(checkMtlsHardwareKeystore());

        for (int i = 0; i < results.size(); i++) {
            Result r = results.get(i);
            sb.append(String.format(Locale.US, "%02d. %s\n", i + 1, r.name));
            sb.append("    状态: ").append(r.status).append("\n");
            sb.append("    说明: ").append(r.detail).append("\n\n");
        }

        sb.append("判定说明\n");
        sb.append("- PASS: 本机已完成对应本地密码学操作或可拿到证明材料；若服务端验证通过，才可作为不可伪造信号。\n");
        sb.append("- PARTIAL: 只能检测到硬件/系统能力或缺少服务端、厂商 SDK、权限、业务配置。\n");
        sb.append("- FAIL: 当前设备/系统/API 不支持，或本地操作失败。\n\n");
        sb.append("服务端必须做三件事：随机 nonce/challenge、验签、验证证书链/签名链。客户端本地显示结果仅供调试。\n");
        sb.append("点击“查看证书链”可生成并显示 TEE/StrongBox attestation 证书链摘要和 PEM，便于复制到服务端/openssl 调试。\n");

        return new ProbeReport(results, sb.toString());
    }

    private void addHeader(StringBuilder sb) {
        sb.append("设备信息\n");
        sb.append("Android: ").append(Build.VERSION.RELEASE).append(" / API ").append(Build.VERSION.SDK_INT).append("\n");
        sb.append("Brand/Model: ").append(Build.BRAND).append(" / ").append(Build.MODEL).append("\n");
        sb.append("Manufacturer: ").append(Build.MANUFACTURER).append("\n");
        sb.append("StrongBox feature: ").append(hasFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)).append("\n");
        sb.append("AndroidKeyStore provider: tested below\n");
        sb.append("Local demo challenge(base64): ").append(b64(demoChallenge)).append("\n");
        sb.append("\n检测结果\n\n");
    }

    private Result checkStrongBoxSigning() {
        String name = "StrongBox 私钥签名";
        if (Build.VERSION.SDK_INT < 28) return fail(name, "需要 Android 9/API 28+ 的 StrongBox API。服务端版应由服务端下发 challenge。 ");
        if (!hasFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) return fail(name, "PackageManager 未声明 android.hardware.strongbox_keystore。 ");
        String alias = "probe_strongbox_sign";
        try {
            deleteAlias(alias);
            generateEcKey(alias, null, true);
            byte[] sig = sign(alias, demoChallenge);
            X509Certificate cert = firstCert(alias);
            boolean ok = verify(cert, demoChallenge, sig);
            boolean hw = isInsideSecureHardware(alias);
            String hwText = hardwareInfo(alias);
            if (ok && hw) return pass(name, "StrongBox 生成私钥并完成 ECDSA 签名/本地验签。签名长度=" + sig.length + "。" + hwText);
            if (ok) return partial(name, "签名可用，但 KeyInfo 未确认 insideSecureHardware=true；请以服务端证书链验证为准。" + hwText);
            return fail(name, "签名生成但本地验签失败。" + hwText);
        } catch (Throwable t) {
            return fail(name, "StrongBox 签名失败: " + shortErr(t));
        }
    }

    private Result checkStrongBoxAttestation() {
        String name = "StrongBox Key Attestation 证书链";
        if (Build.VERSION.SDK_INT < 28) return fail(name, "需要 Android 9/API 28+ 才能显式请求 StrongBox。 ");
        if (!hasFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) return fail(name, "设备未声明 StrongBox KeyStore。 ");
        String alias = "probe_strongbox_attest";
        try {
            deleteAlias(alias);
            generateEcKey(alias, demoChallenge, true);
            Certificate[] chain = certChain(alias);
            AttestationInfo info = inspectAttestation(chain);
            if (info.attestationExtFound && info.challengeMatches && info.isStrongBoxSecurityLevel()) {
                return pass(name, "拿到 StrongBox attestation 证书链 length=" + chain.length + "；" + info.summary());
            }
            return partial(name, "拿到证书链，但未完整确认 StrongBox attestation/challenge/securityLevel；生产环境必须服务端验链。length=" + chain.length + "；" + info.summary());
        } catch (Throwable t) {
            return fail(name, "生成/读取 StrongBox attestation 失败: " + shortErr(t));
        }
    }

    private Result checkTeeSigning() {
        String name = "TEE / KeyMint / Keymaster 私钥签名";
        String alias = "probe_tee_sign";
        try {
            deleteAlias(alias);
            generateEcKey(alias, null, false);
            byte[] sig = sign(alias, demoChallenge);
            X509Certificate cert = firstCert(alias);
            boolean ok = verify(cert, demoChallenge, sig);
            boolean hw = isInsideSecureHardware(alias);
            String hwText = hardwareInfo(alias);
            if (ok && hw) return pass(name, "AndroidKeyStore 生成硬件内不可导出私钥并完成 ECDSA 签名/本地验签。签名长度=" + sig.length + "。" + hwText);
            if (ok) return fail(name, "AndroidKeyStore 可签名，但 KeyInfo 显示不在安全硬件内；不满足 TEE/KeyMint/Keymaster 硬件私钥条件。" + hwText);
            return fail(name, "签名生成但本地验签失败。" + hwText);
        } catch (Throwable t) {
            return fail(name, "TEE/Keymaster 签名失败: " + shortErr(t));
        }
    }

    private Result checkTeeAttestation() {
        String name = "TEE / KeyMint / Keymaster Key Attestation 证书链";
        if (Build.VERSION.SDK_INT < 24) return fail(name, "Key Attestation 需要 Android 7/API 24+。 ");
        String alias = "probe_tee_attest";
        try {
            deleteAlias(alias);
            generateEcKey(alias, demoChallenge, false);
            Certificate[] chain = certChain(alias);
            AttestationInfo info = inspectAttestation(chain);
            if (info.attestationExtFound && info.challengeMatches && info.isTrustedEnvironmentSecurityLevel()) {
                return pass(name, "拿到 TEE/KeyMint/Keymaster attestation 证书链 length=" + chain.length + "；" + info.summary());
            }
            if (info.attestationExtFound && info.challengeMatches) {
                return partial(name, "拿到 attestation 证书链并匹配 challenge，但 securityLevel 未确认是 TEE；生产环境必须服务端验链。length=" + chain.length + "；" + info.summary());
            }
            return fail(name, "未能确认有效 Android Key Attestation 扩展或 challenge。length=" + chain.length + "；" + info.summary());
        } catch (Throwable t) {
            return fail(name, "生成/读取 TEE attestation 失败: " + shortErr(t));
        }
    }

    private Result checkVerifiedBootFields() {
        String name = "Android Key Attestation verifiedBootState / deviceLocked 等硬件证明字段";
        if (Build.VERSION.SDK_INT < 24) return fail(name, "需要 Android 7/API 24+ Key Attestation。 ");
        String alias = "probe_boot_fields";
        try {
            deleteAlias(alias);
            generateEcKey(alias, demoChallenge, false);
            Certificate[] chain = certChain(alias);
            AttestationInfo info = inspectAttestation(chain);
            if (info.rootOfTrustFound && info.verifiedBootState != null && info.deviceLocked != null) {
                return pass(name, "已从 Android Key Attestation 扩展解析 RootOfTrust：verifiedBootState=" + info.verifiedBootState + ", deviceLocked=" + info.deviceLocked + "；" + info.summary());
            }
            if (info.attestationExtFound) {
                return partial(name, "发现 Android Key Attestation 扩展，但未解析到完整 RootOfTrust 字段；可能是设备实现差异或解析不支持。生产环境请服务端 ASN.1 解析并验链。" + info.summary());
            }
            return fail(name, "证书中未发现 Android Key Attestation 扩展 OID。" + info.summary());
        } catch (Throwable t) {
            return fail(name, "读取 verifiedBoot 相关证明失败: " + shortErr(t));
        }
    }

    private Result checkVendorIntegrityServices() {
        String name = "厂商安全服务的服务端签名 verdict（华为/荣耀/小米/OPPO/vivo 等 integrity token）";
        List<String> found = new ArrayList<>();
        PackageManager pm = getPackageManager();
        String[] pkgs = new String[] {
                "com.huawei.hwid", "com.huawei.hms", "com.hihonor.id", "com.xiaomi.xmsf",
                "com.heytap.openid", "com.coloros.securitypermission", "com.vivo.identifier", "com.bbk.account"
        };
        for (String p : pkgs) {
            try { pm.getPackageInfo(p, 0); found.add(p); } catch (Throwable ignored) {}
        }
        String manu = (Build.MANUFACTURER + " " + Build.BRAND).toLowerCase(Locale.US);
        boolean knownBrand = manu.contains("huawei") || manu.contains("honor") || manu.contains("xiaomi") || manu.contains("redmi") || manu.contains("oppo") || manu.contains("oneplus") || manu.contains("realme") || manu.contains("vivo");
        if (!found.isEmpty()) return partial(name, "检测到可能相关的厂商基础服务包: " + found + "。但真正 verdict 必须接入对应厂商 SDK/后台并由服务端验证厂商签名 token。 ");
        if (knownBrand) return partial(name, "设备品牌可能支持厂商完整性服务，但未识别到具体 SDK/服务包。需接入厂商 SDK 并做服务端验证。 ");
        return partial(name, "Android 无统一标准 API 可直接检测所有厂商 verdict。需按厂商分别集成 SDK，并由服务端发 nonce、验签。 ");
    }

    private Result checkPlayIntegrity() {
        String name = "Play Integrity API 的 Google 签名 JWS";
        boolean hasGms = hasPackage("com.google.android.gms");
        if (hasGms) {
            return partial(name, "检测到 Google Play services。此项目未内置 Play Integrity SDK/API key。生产环境需接入 com.google.android.play:integrity，由服务端生成 nonce 并验证 Google 签名 JWS。 ");
        }
        return fail(name, "未检测到 com.google.android.gms；通常无法使用 Play Integrity API。 ");
    }

    private Result checkCarrierGateway() {
        String name = "运营商网关认证返回的运营商签名 token";
        boolean telephony = hasFeature(PackageManager.FEATURE_TELEPHONY);
        String network = "unknown";
        try {
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                CharSequence n = tm.getNetworkOperatorName();
                if (n != null && n.length() > 0) network = n.toString();
            }
        } catch (Throwable ignored) {}
        if (telephony) return partial(name, "设备有蜂窝通信能力，当前运营商名称=" + network + "。网关认证 token 需要接入运营商 SDK/接口，并通常要求移动数据网络、服务端 challenge 和运营商侧验签。 ");
        return fail(name, "设备未声明蜂窝通信能力，无法进行运营商网关认证。 ");
    }

    private Result checkSimEsimSePrivateKey() {
        String name = "SIM / eSIM / SE 内私钥签名";
        boolean telephony = hasFeature(PackageManager.FEATURE_TELEPHONY);
        boolean ese = hasFeature(PackageManager.FEATURE_SE_OMAPI_ESE);
        boolean uicc = hasFeature(PackageManager.FEATURE_SE_OMAPI_UICC);
        boolean sd = hasFeature(PackageManager.FEATURE_SE_OMAPI_SD);
        boolean omapi = Build.VERSION.SDK_INT >= 28 && (ese || uicc || sd);
        if (telephony || omapi) {
            return partial(name, "检测到相关能力: telephony=" + telephony + ", OMAPI_UICC=" + uicc + ", OMAPI_eSE=" + ese + ", OMAPI_SD=" + sd + "。实际私钥签名需要 SIM/eSIM/SE applet、访问控制规则、运营商/发行方授权，且服务端验证签名/证书链。 ");
        }
        return fail(name, "未检测到 telephony 或 OMAPI Secure Element 能力。 ");
    }

    private Result checkEseSecureElement() {
        String name = "eSE / Secure Element 私钥签名";
        boolean ese = Build.VERSION.SDK_INT >= 28 && hasFeature(PackageManager.FEATURE_SE_OMAPI_ESE);
        boolean sd = Build.VERSION.SDK_INT >= 28 && hasFeature(PackageManager.FEATURE_SE_OMAPI_SD);
        boolean nfc = NfcAdapter.getDefaultAdapter(this) != null;
        if (ese || sd) return partial(name, "检测到 OMAPI Secure Element: eSE=" + ese + ", SD=" + sd + "。是否能签名取决于 SE applet 和访问控制；需服务端 challenge/验签。 ");
        if (nfc) return partial(name, "检测到 NFC，但未检测到标准 OMAPI eSE/SD feature。NFC 不等于可访问 eSE 私钥；需要具体 applet/权限。 ");
        return fail(name, "未检测到 eSE/SD OMAPI，也未检测到 NFC。 ");
    }

    private Result checkFido2Passkey() {
        String name = "FIDO2 / Passkey / 硬件安全密钥签名";
        boolean gms = hasPackage("com.google.android.gms");
        boolean biometric = hasFeature(PackageManager.FEATURE_FINGERPRINT) || hasFeature("android.hardware.biometrics.face") || hasFeature("android.hardware.biometrics.iris");
        boolean usbHost = hasFeature(PackageManager.FEATURE_USB_HOST);
        boolean nfc = NfcAdapter.getDefaultAdapter(this) != null;
        if (gms || biometric || usbHost || nfc) {
            return partial(name, "可能具备 FIDO2/Passkey 条件: GMS=" + gms + ", biometric=" + biometric + ", USB host=" + usbHost + ", NFC=" + nfc + "。实际需要调用 FIDO2/Credential Manager/WebAuthn，让认证器对服务端 challenge 签名，并在服务端验证 attestation/assertion。 ");
        }
        return fail(name, "未检测到常见 FIDO2/Passkey 条件（GMS/强生物识别/USB host/NFC）。 ");
    }

    private Result checkMtlsHardwareKeystore() {
        String name = "硬件 Keystore 私钥参与的 mTLS 客户端证书握手";
        String alias = "probe_mtls_key";
        try {
            deleteAlias(alias);
            generateEcKey(alias, null, false);
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, null);
            boolean hw = isInsideSecureHardware(alias);
            String hwText = hardwareInfo(alias);
            if (!hw) return fail(name, "已生成 AndroidKeyStore 私钥，但 KeyInfo 显示不在安全硬件内；不满足硬件 Keystore mTLS 条件。" + hwText);
            return partial(name, "已生成硬件内 AndroidKeyStore 客户端私钥，并初始化 KeyManagerFactory。完整 mTLS 还需要服务端请求客户端证书、验证证书链，并完成真实 TLS 握手。" + hwText);
        } catch (Throwable t) {
            return fail(name, "mTLS keystore 准备失败: " + shortErr(t));
        }
    }


    public String showCertificateChains() {
        try {
            return collectCertificateChains();
        } finally {
            cleanup();
        }
    }

    private String collectCertificateChains() {
        StringBuilder sb = new StringBuilder();
        addHeader(sb);
        sb.append("证书链查看\n\n");
        sb.append("说明：这里生成新的本地 demo attestation key，并用本次操作的 SecureRandom 随机 challenge 作为 challenge。\n");
        sb.append("生产环境请把 PEM 证书链、公钥签名和服务端 nonce 一起发到服务端，由服务端验证 Google/Android attestation 根链、challenge、签名和 RootOfTrust 字段。\n\n");

        appendAttestationChain(sb, "TEE / KeyMint / Keymaster Attestation", "probe_view_tee_attest", false);
        sb.append("\n");
        appendAttestationChain(sb, "StrongBox Attestation", "probe_view_strongbox_attest", true);

        return sb.toString();
    }

    private void appendAttestationChain(StringBuilder sb, String title, String alias, boolean strongBox) {
        sb.append("==============================\n");
        sb.append(title).append("\n");
        sb.append("==============================\n");
        sb.append("alias: ").append(alias).append("\n");
        sb.append("challenge(base64): ").append(b64(demoChallenge)).append("\n");
        if (Build.VERSION.SDK_INT < 24) {
            sb.append("状态: FAIL - Key Attestation 需要 Android 7/API 24+。\n");
            return;
        }
        if (strongBox) {
            if (Build.VERSION.SDK_INT < 28) {
                sb.append("状态: FAIL - StrongBox 需要 Android 9/API 28+。\n");
                return;
            }
            if (!hasFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                sb.append("状态: FAIL - 设备未声明 android.hardware.strongbox_keystore。\n");
                return;
            }
        }
        try {
            deleteAlias(alias);
            generateEcKey(alias, demoChallenge, strongBox);
            Certificate[] chain = certChain(alias);
            AttestationInfo info = inspectAttestation(chain);
            sb.append("状态: 已读取（未进行服务端信任链验证）\n");
            sb.append("私钥: 硬件/Keystore 内生成，不可导出\n");
            sb.append("chainLength: ").append(chain.length).append("\n");
            sb.append("attestationInfo: ").append(info.summary()).append("\n\n");
            appendCertificateChainPemAndSummary(sb, chain);
        } catch (Throwable t) {
            sb.append("状态: FAIL - ").append(shortErr(t)).append("\n");
        }
    }

    private void appendCertificateChainPemAndSummary(StringBuilder sb, Certificate[] chain) throws Exception {
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            sb.append("----- Certificate ").append(i).append(" / ").append(chain.length - 1).append(" -----\n");
            sb.append("Subject: ").append(cert.getSubjectX500Principal().getName()).append("\n");
            sb.append("Issuer: ").append(cert.getIssuerX500Principal().getName()).append("\n");
            sb.append("Serial(hex): ").append(cert.getSerialNumber().toString(16)).append("\n");
            sb.append("NotBefore: ").append(cert.getNotBefore()).append("\n");
            sb.append("NotAfter: ").append(cert.getNotAfter()).append("\n");
            sb.append("SigAlg: ").append(cert.getSigAlgName()).append("\n");
            sb.append("PublicKey: ").append(cert.getPublicKey().getAlgorithm()).append(" / ").append(cert.getPublicKey().getFormat()).append("\n");
            sb.append("SHA256 Fingerprint: ").append(sha256Hex(cert.getEncoded())).append("\n");
            sb.append("SelfSignedSubjectIssuer: ").append(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())).append("\n");
            if (i == 0) {
                byte[] ext = cert.getExtensionValue(ANDROID_KEY_ATTESTATION_OID);
                sb.append("AndroidKeyAttestationOID: ").append(ext != null ? ("present, extLen=" + ext.length) : "absent").append("\n");
            }
            sb.append("PEM:\n").append(pemCertificate(cert)).append("\n");
        }
    }

    private String pemCertificate(X509Certificate cert) throws Exception {
        String body = b64(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + wrap64(body) + "\n-----END CERTIFICATE-----\n";
    }

    private String wrap64(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i += 64) {
            if (i > 0) out.append('\n');
            out.append(s, i, Math.min(i + 64, s.length()));
        }
        return out.toString();
    }

    private String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return hex(md.digest(data));
    }

    private String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (int i = 0; i < data.length; i++) {
            if (i > 0) sb.append(':');
            int v = data[i] & 0xff;
            if (v < 16) sb.append('0');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    private void generateEcKey(String alias, byte[] attestationChallenge, boolean strongBox) throws Exception {
        temporaryAliases.add(alias);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false);
        if (Build.VERSION.SDK_INT >= 24 && attestationChallenge != null) b.setAttestationChallenge(attestationChallenge);
        if (Build.VERSION.SDK_INT >= 28) b.setIsStrongBoxBacked(strongBox);
        kpg.initialize(b.build());
        kpg.generateKeyPair();
    }

    private byte[] sign(String alias, byte[] data) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(pk);
        s.update(data);
        return s.sign();
    }

    private boolean verify(X509Certificate cert, byte[] data, byte[] sigBytes) throws Exception {
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(cert.getPublicKey());
        v.update(data);
        return v.verify(sigBytes);
    }

    private Certificate[] certChain(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(alias);
        if (chain == null || chain.length == 0) throw new IllegalStateException("empty certificate chain");
        return chain;
    }

    private X509Certificate firstCert(String alias) throws Exception {
        return (X509Certificate) certChain(alias)[0];
    }

    private AttestationInfo inspectAttestation(Certificate[] chain) throws Exception {
        AttestationInfo info = new AttestationInfo();
        info.chainLength = chain == null ? 0 : chain.length;
        if (chain == null) return info;
        for (int i = 0; i < chain.length; i++) {
            X509Certificate c = (X509Certificate) chain[i];
            if (i == 0) {
                info.leafSubject = c.getSubjectX500Principal().getName();
                byte[] ext = c.getExtensionValue(ANDROID_KEY_ATTESTATION_OID);
                if (ext != null) {
                    info.attestationExtFound = true;
                    info.attestationExtLen = ext.length;
                    info.attestationExtPrefixB64 = b64(slice(ext, 0, Math.min(48, ext.length)));
                    try {
                        byte[] keyDescription = unwrapOuterOctetString(ext);
                        parseKeyDescription(keyDescription, info);
                    } catch (Throwable t) {
                        info.parseError = shortErr(t);
                    }
                }
            }
            if (c.getIssuerX500Principal().equals(c.getSubjectX500Principal())) info.selfSignedCount++;
        }
        return info;
    }

    private byte[] unwrapOuterOctetString(byte[] ext) throws Exception {
        DerValue outer = DerValue.readOne(ext, 0, ext.length);
        if (outer.isUniversal(4)) return outer.valueBytes();
        return ext;
    }

    private void parseKeyDescription(byte[] der, AttestationInfo info) throws Exception {
        DerValue seq = DerValue.readOne(der, 0, der.length);
        if (!seq.isUniversal(16)) throw new IllegalArgumentException("KeyDescription is not SEQUENCE");
        List<DerValue> c = seq.children();
        if (c.size() < 8) throw new IllegalArgumentException("KeyDescription children < 8: " + c.size());
        info.attestationVersion = safeInt(c.get(0));
        info.attestationSecurityLevel = securityLevelName(safeInt(c.get(1)));
        info.keymasterVersion = safeInt(c.get(2));
        info.keymasterSecurityLevel = securityLevelName(safeInt(c.get(3)));
        byte[] challenge = c.get(4).valueBytes();
        info.challengeMatches = Arrays.equals(demoChallenge, challenge);
        parseAuthorizationList(c.get(6), "softwareEnforced", info);
        parseAuthorizationList(c.get(7), "teeEnforced", info);
    }

    private void parseAuthorizationList(DerValue list, String listName, AttestationInfo info) throws Exception {
        if (!list.isUniversal(16)) return;
        List<DerValue> tags = list.children();
        for (DerValue tag : tags) {
            if (tag.tagClass == 2 && tag.tagNo == 704) {
                List<DerValue> inner = tag.children();
                if (!inner.isEmpty()) {
                    parseRootOfTrust(inner.get(0), listName, info);
                }
            } else if (tag.tagClass == 2 && tag.tagNo == 705) {
                Long v = firstInnerInteger(tag);
                if (v != null) info.osVersion = String.valueOf(v);
            } else if (tag.tagClass == 2 && tag.tagNo == 706) {
                Long v = firstInnerInteger(tag);
                if (v != null) info.osPatchLevel = String.valueOf(v);
            } else if (tag.tagClass == 2 && tag.tagNo == 718) {
                Long v = firstInnerInteger(tag);
                if (v != null) info.bootPatchLevel = String.valueOf(v);
            }
        }
    }

    private void parseRootOfTrust(DerValue rot, String listName, AttestationInfo info) throws Exception {
        if (!rot.isUniversal(16)) throw new IllegalArgumentException("RootOfTrust is not SEQUENCE");
        List<DerValue> r = rot.children();
        if (r.size() < 3) throw new IllegalArgumentException("RootOfTrust children < 3: " + r.size());
        info.rootOfTrustFound = true;
        info.rootOfTrustList = listName;
        info.verifiedBootKeyLen = r.get(0).valueLength;
        info.deviceLocked = r.get(1).asBoolean();
        info.verifiedBootState = verifiedBootStateName(safeInt(r.get(2)));
        if (r.size() > 3) info.verifiedBootHashLen = r.get(3).valueLength;
    }

    private Long firstInnerInteger(DerValue explicit) {
        try {
            List<DerValue> inner = explicit.children();
            if (inner.isEmpty()) return null;
            return inner.get(0).asIntegerLike();
        } catch (Throwable t) {
            return null;
        }
    }

    private int safeInt(DerValue v) throws Exception {
        long n = v.asIntegerLike();
        if (n > Integer.MAX_VALUE || n < Integer.MIN_VALUE) throw new IllegalArgumentException("integer out of int range: " + n);
        return (int) n;
    }

    private String securityLevelName(int v) {
        if (v == 0) return "Software(0)";
        if (v == 1) return "TrustedEnvironment(1)";
        if (v == 2) return "StrongBox(2)";
        return "Unknown(" + v + ")";
    }

    private String verifiedBootStateName(int v) {
        if (v == 0) return "Verified(0)";
        if (v == 1) return "SelfSigned(1)";
        if (v == 2) return "Unverified(2)";
        if (v == 3) return "Failed(3)";
        return "Unknown(" + v + ")";
    }

    private boolean isInsideSecureHardware(String alias) {
        if (Build.VERSION.SDK_INT < 23) return false;
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
            KeyFactory kf = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = kf.getKeySpec(pk, KeyInfo.class);
            return info.isInsideSecureHardware();
        } catch (Throwable t) {
            return false;
        }
    }

    private String hardwareInfo(String alias) {
        if (Build.VERSION.SDK_INT < 23) return "";
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
            KeyFactory kf = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = kf.getKeySpec(pk, KeyInfo.class);
            return " insideSecureHardware=" + info.isInsideSecureHardware();
        } catch (Throwable t) {
            return " hardwareInfo=unavailable(" + shortErr(t) + ")";
        }
    }

    private void deleteAlias(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(alias)) ks.deleteEntry(alias);
        } catch (Throwable ignored) {}
    }

    private boolean hasPackage(String pkg) {
        try { getPackageManager().getPackageInfo(pkg, 0); return true; }
        catch (Throwable t) { return false; }
    }

    private boolean hasFeature(String feature) {
        try { return getPackageManager().hasSystemFeature(feature); }
        catch (Throwable t) { return false; }
    }

    private String b64(byte[] data) {
        if (data == null) return "null";
        return android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP);
    }

    private byte[] slice(byte[] a, int start, int end) {
        byte[] r = new byte[Math.max(0, end - start)];
        for (int i = 0; i < r.length; i++) r[i] = a[start + i];
        return r;
    }

    private String shortErr(Throwable t) {
        if (t == null) return "unknown";
        String msg = t.getMessage();
        if (msg == null) msg = "";
        msg = msg.replace('\n', ' ');
        if (msg.length() > 180) msg = msg.substring(0, 180) + "...";
        return t.getClass().getSimpleName() + (msg.isEmpty() ? "" : ": " + msg);
    }

    private Result pass(String name, String detail) { return new Result(name, "PASS", detail); }
    private Result partial(String name, String detail) { return new Result(name, "PARTIAL", detail); }
    private Result fail(String name, String detail) { return new Result(name, "FAIL", detail); }

    private void cleanup() {
        for (String alias : temporaryAliases) deleteAlias(alias);
        temporaryAliases.clear();
    }

    public static final class ProbeReport {
        public final List<Result> results;
        public final String text;
        ProbeReport(List<Result> results, String text) {
            this.results = results;
            this.text = text;
        }
    }

    public static final class Result {
        public final String name;
        public final String status;
        public final String detail;
        Result(String name, String status, String detail) { this.name = name; this.status = status; this.detail = detail; }
    }

    private static class AttestationInfo {
        int chainLength;
        boolean attestationExtFound;
        int attestationExtLen;
        String attestationExtPrefixB64 = "";
        int selfSignedCount;
        String leafSubject = "";
        String parseError = "";

        int attestationVersion = -1;
        String attestationSecurityLevel = "unknown";
        int keymasterVersion = -1;
        String keymasterSecurityLevel = "unknown";
        boolean challengeMatches = false;

        boolean rootOfTrustFound = false;
        String rootOfTrustList = "";
        Integer verifiedBootKeyLen = null;
        Boolean deviceLocked = null;
        String verifiedBootState = null;
        Integer verifiedBootHashLen = null;
        String osVersion = "";
        String osPatchLevel = "";
        String bootPatchLevel = "";

        boolean isStrongBoxSecurityLevel() {
            return attestationSecurityLevel.contains("StrongBox") || keymasterSecurityLevel.contains("StrongBox");
        }

        boolean isTrustedEnvironmentSecurityLevel() {
            return attestationSecurityLevel.contains("TrustedEnvironment") || keymasterSecurityLevel.contains("TrustedEnvironment");
        }

        String summary() {
            return "leafSubject=" + leafSubject +
                    ", androidAttestationOidFound=" + attestationExtFound +
                    ", extLen=" + attestationExtLen +
                    ", challengeMatches=" + challengeMatches +
                    ", attestationVersion=" + attestationVersion +
                    ", attestationSecurityLevel=" + attestationSecurityLevel +
                    ", keymasterVersion=" + keymasterVersion +
                    ", keymasterSecurityLevel=" + keymasterSecurityLevel +
                    ", rootOfTrustFound=" + rootOfTrustFound +
                    ", rootOfTrustList=" + rootOfTrustList +
                    ", deviceLocked=" + deviceLocked +
                    ", verifiedBootState=" + verifiedBootState +
                    ", verifiedBootKeyLen=" + verifiedBootKeyLen +
                    ", verifiedBootHashLen=" + verifiedBootHashLen +
                    ", osVersion=" + osVersion +
                    ", osPatchLevel=" + osPatchLevel +
                    ", bootPatchLevel=" + bootPatchLevel +
                    ", selfSignedCerts=" + selfSignedCount +
                    (parseError.length() == 0 ? "" : ", parseError=" + parseError) +
                    ", extPrefixB64=" + attestationExtPrefixB64;
        }
    }

    private static class DerValue {
        final byte[] data;
        final int start;
        final int headerLength;
        final int valueOffset;
        final int valueLength;
        final int end;
        final int tagClass;
        final boolean constructed;
        final int tagNo;

        private DerValue(byte[] data, int start, int headerLength, int valueOffset, int valueLength, int tagClass, boolean constructed, int tagNo) {
            this.data = data;
            this.start = start;
            this.headerLength = headerLength;
            this.valueOffset = valueOffset;
            this.valueLength = valueLength;
            this.end = valueOffset + valueLength;
            this.tagClass = tagClass;
            this.constructed = constructed;
            this.tagNo = tagNo;
        }

        static DerValue readOne(byte[] data, int offset, int limit) throws Exception {
            if (offset >= limit) throw new IllegalArgumentException("DER offset >= limit");
            int p = offset;
            int first = data[p++] & 0xff;
            int tagClass = (first & 0xc0) >> 6;
            boolean constructed = (first & 0x20) != 0;
            int tagNo = first & 0x1f;
            if (tagNo == 0x1f) {
                tagNo = 0;
                int count = 0;
                while (true) {
                    if (p >= limit) throw new IllegalArgumentException("truncated high-tag-number");
                    int b = data[p++] & 0xff;
                    tagNo = (tagNo << 7) | (b & 0x7f);
                    count++;
                    if ((b & 0x80) == 0) break;
                    if (count > 5) throw new IllegalArgumentException("high-tag-number too long");
                }
            }
            if (p >= limit) throw new IllegalArgumentException("missing length");
            int lb = data[p++] & 0xff;
            int len;
            if ((lb & 0x80) == 0) {
                len = lb;
            } else {
                int n = lb & 0x7f;
                if (n == 0) throw new IllegalArgumentException("indefinite length not allowed in DER");
                if (n > 4) throw new IllegalArgumentException("length too long");
                if (p + n > limit) throw new IllegalArgumentException("truncated length");
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | (data[p++] & 0xff);
            }
            if (len < 0 || p + len > limit) throw new IllegalArgumentException("value length exceeds limit");
            return new DerValue(data, offset, p - offset, p, len, tagClass, constructed, tagNo);
        }

        boolean isUniversal(int universalTagNo) {
            return tagClass == 0 && tagNo == universalTagNo;
        }

        byte[] valueBytes() {
            byte[] out = new byte[valueLength];
            System.arraycopy(data, valueOffset, out, 0, valueLength);
            return out;
        }

        List<DerValue> children() throws Exception {
            List<DerValue> out = new ArrayList<>();
            int p = valueOffset;
            while (p < end) {
                DerValue v = readOne(data, p, end);
                out.add(v);
                p = v.end;
            }
            if (p != end) throw new IllegalArgumentException("child parse did not end exactly");
            return out;
        }

        long asIntegerLike() throws Exception {
            if (!(isUniversal(2) || isUniversal(10))) throw new IllegalArgumentException("not INTEGER/ENUMERATED tag=" + tagNo);
            if (valueLength == 0 || valueLength > 8) throw new IllegalArgumentException("bad integer length=" + valueLength);
            long v = 0;
            for (int i = 0; i < valueLength; i++) v = (v << 8) | (data[valueOffset + i] & 0xffL);
            if ((data[valueOffset] & 0x80) != 0 && valueLength < 8) v -= (1L << (valueLength * 8));
            return v;
        }

        boolean asBoolean() throws Exception {
            if (!isUniversal(1)) throw new IllegalArgumentException("not BOOLEAN");
            if (valueLength != 1) throw new IllegalArgumentException("bad boolean length=" + valueLength);
            return data[valueOffset] != 0;
        }
    }
}
