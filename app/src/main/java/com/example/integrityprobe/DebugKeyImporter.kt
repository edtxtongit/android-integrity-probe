package com.example.integrityprobe

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.UUID

/** Import, inspect and sign with the imported key. Never silently retry in software. */
object DebugKeyImporter {
    data class ImportResult(val success: Boolean, val hardwareBacked: Boolean, val detail: String)

    fun importAndVerify(material: DebugKeyGenerator.Material, strongBox: Boolean): ImportResult {
        val alias = "probe_debug_${UUID.randomUUID()}"
        var store: KeyStore? = null
        var imported = false
        var success = false
        var hardware = false
        val detail = StringBuilder()
        detail.appendLine("请求目标: ${if (strongBox) "StrongBox" else "Android Keystore（检查实际存储级别）"}")
        try {
            require(!strongBox || Build.VERSION.SDK_INT >= 28) { "StrongBox 导入需要 Android 9 / API 28+" }
            val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
            if (material.keyPair.private.algorithm == "RSA") {
                protection.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            if (strongBox && Build.VERSION.SDK_INT >= 28) protection.setIsStrongBoxBacked(true)
            store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            store.setEntry(alias, KeyStore.PrivateKeyEntry(material.keyPair.private, material.chain), protection.build())
            imported = true
            val privateKey = store.getKey(alias, null) as PrivateKey
            val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo::class.java)
            @Suppress("DEPRECATION")
            hardware = info.isInsideSecureHardware
            val level = if (Build.VERSION.SDK_INT >= 31) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "软件"
                    else -> "未知 (${info.securityLevel})"
                }
            } else {
                if (hardware) "安全硬件（此 API 无法区分 TEE / StrongBox）" else "软件 / 未确认硬件"
            }
            detail.appendLine("导入: 成功\n实际存储级别: $level\ninsideSecureHardware: $hardware")
            detail.appendLine("Key origin: ${info.origin}（IMPORTED=${KeyProperties.ORIGIN_IMPORTED}）")
            detail.appendLine("Keystore 私钥句柄可导出: ${privateKey.encoded != null}")
            val storedChain = requireNotNull(store.getCertificateChain(alias)) { "导入后没有证书链" }
            check(storedChain.size == material.chain.size && storedChain.indices.all {
                storedChain[it].encoded.contentEquals(material.chain[it].encoded)
            }) { "Keystore 返回的证书链与导入材料不一致" }
            detail.appendLine("证书链: 已读回，与导入的调试链一致（不是硬件 Attestation）")
            val signer = Signature.getInstance(material.signatureAlgorithm)
            signer.initSign(privateKey)
            signer.update(material.challenge)
            val signature = signer.sign()
            val verifier = Signature.getInstance(material.signatureAlgorithm)
            verifier.initVerify(storedChain.first().publicKey)
            verifier.update(material.challenge)
            check(verifier.verify(signature)) { "导入后的签名验证失败" }
            detail.appendLine("Keystore 签名 / 叶证书验签: PASS")
            detail.appendLine("签名 (Base64): ${Base64.encodeToString(signature, Base64.NO_WRAP)}")
            if (strongBox) {
                check(hardware) { "请求了 StrongBox，但系统未确认安全硬件存储" }
                if (Build.VERSION.SDK_INT >= 31) {
                    check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) { "实际级别不是请求的 StrongBox" }
                }
            }
            if (!hardware) detail.appendLine("注意：未确认硬件存储，不能当作 TEE / StrongBox 导入成功。")
            success = true
        } catch (e: Exception) {
            detail.appendLine("${if (imported) "导入后的检查/签名" else "导入"}: FAIL")
            detail.appendLine("${e.javaClass.simpleName}: ${e.message ?: "系统未提供详细原因"}")
            detail.appendLine("没有降级重试；上方生成的私钥及调试证书仍可复制。")
        } finally {
            try {
                store?.let {
                    if (it.containsAlias(alias)) it.deleteEntry(alias)
                    detail.appendLine("临时 Keystore 条目已清理；本次仅用于导入和签名调试。")
                }
            } catch (e: Exception) {
                detail.appendLine("临时条目清理失败: $alias\n${e.javaClass.simpleName}: ${e.message}")
            }
        }
        return ImportResult(success, hardware, detail.toString())
    }
}
