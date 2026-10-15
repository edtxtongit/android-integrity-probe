package com.example.integrityprobe

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.lang.reflect.InvocationTargetException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/** Experimental vendor path, not a claim of official Honor 400 compatibility. */
internal class HuaweiKeyBackend : VendorKeyBackend {
    private lateinit var store: KeyStore

    override fun providers(): String = Security.getProviders().joinToString("\n") { provider ->
        val services = provider.services.filter {
            it.type == "KeyStore" || (it.type == "KeyPairGenerator" && it.algorithm == "EC") ||
                (it.type == "Signature" && it.algorithm.equals(SigningText.ALGORITHM, true))
        }.joinToString { "${it.type}.${it.algorithm}" }
        "${provider.name} [${provider.javaClass.name}]: $services"
    }

    override fun install(): String {
        val alreadyInstalled = Security.getProvider(PROVIDER) != null
        if (!alreadyInstalled) {
            // Do not bypass hidden API restrictions or load a replacement provider from elsewhere.
            try {
                Class.forName(PROVIDER_CLASS).getMethod("install").invoke(null)
            } catch (e: InvocationTargetException) {
                val cause = e.targetException
                if (cause is Exception) throw cause
                if (cause is Error) throw cause
                throw e
            }
        }
        val provider = checkNotNull(Security.getProvider(PROVIDER)) { "install 返回，但未注册 $PROVIDER" }
        check(provider.getService("KeyStore", STORE) != null) { "Provider 未提供 KeyStore.$STORE" }
        check(provider.getService("KeyPairGenerator", "EC") != null) { "Provider 未提供 EC 生成器" }
        check(provider.getService("Signature", SigningText.ALGORITHM) != null) { "Provider 未提供 ${SigningText.ALGORITHM}" }
        return "${if (alreadyInstalled) "已注册，无需重复安装" else "反射 install 成功"}\n实现: ${provider.javaClass.name}\n${provider.info}"
    }

    override fun open() {
        store = KeyStore.getInstance(STORE, PROVIDER).apply { load(null) }
        check(store.provider.name == PROVIDER) { "KeyStore Provider 不匹配" }
    }

    override fun contains(alias: String): Boolean = store.containsAlias(alias)

    override fun generate(alias: String, challenge: ByteArray) {
        if (Build.VERSION.SDK_INT < 24) {
            throw UnsupportedOperationException("标准 KeyGenParameterSpec attestation 参数需要 API 24+")
        }
        check(!store.containsAlias(alias)) { "alias 已存在，拒绝覆盖" }
        // Supported by the examined P40 implementation; Honor/other versions may reject it.
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setAttestationChallenge(challenge)
            .build()
        KeyPairGenerator.getInstance("EC", PROVIDER).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    override fun chain(alias: String): List<X509Certificate> =
        (store.getCertificateChain(alias) ?: error("alias 没有证书链")).map { cert ->
            cert as? X509Certificate ?: error("返回的证书不是 X.509")
        }

    override fun sign(alias: String, bytes: ByteArray): ByteArray {
        val key = store.getKey(alias, null) as? PrivateKey ?: error("未获取到私钥操作句柄")
        check(key.algorithm.equals("EC", ignoreCase = true)) { "现有 alias 不是 EC 私钥，拒绝替换" }
        return Signature.getInstance(SigningText.ALGORITHM, PROVIDER).run {
            initSign(key)
            update(bytes)
            sign()
        }
    }

    override fun delete(alias: String) = store.deleteEntry(alias)

    companion object {
        private const val PROVIDER = "HwUniversalKeyStoreProvider"
        private const val STORE = "HwKeystore"
        private const val PROVIDER_CLASS = "com.huawei.security.keystore.HwUniversalKeyStoreProvider"
    }
}
