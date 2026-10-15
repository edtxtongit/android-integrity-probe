package com.example.integrityprobe

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DebugKeyImporterTest {
    @Test fun importedEcKeySignsWithMatchingCertificateAndIsCleanedUp() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val before = store.aliases().toList().filter { it.startsWith("probe_debug_") }.toSet()
        val material = DebugKeyGenerator().generate("EC", "Import test", 1)
        val result = DebugKeyImporter.importAndVerify(material, false)
        assertTrue(result.detail, result.success)
        assertTrue(result.detail.contains("Keystore 签名 / 叶证书验签: PASS"))
        assertEquals(before, store.aliases().toList().filter { it.startsWith("probe_debug_") }.toSet())
    }

    @Test fun strongBoxEitherVerifiesOrReportsFailureWithoutFallback() {
        val material = DebugKeyGenerator().generate("EC", "StrongBox test", 1)
        val result = DebugKeyImporter.importAndVerify(material, true)
        if (result.success) {
            assertTrue(result.detail, result.hardwareBacked)
            assertTrue(result.detail.contains("Keystore 签名 / 叶证书验签: PASS"))
        } else {
            assertTrue(result.detail.contains("FAIL"))
            assertTrue(result.detail.contains("没有降级重试"))
        }
        assertTrue(material.privateKeyPem.startsWith("-----BEGIN PRIVATE KEY-----"))
    }
}
