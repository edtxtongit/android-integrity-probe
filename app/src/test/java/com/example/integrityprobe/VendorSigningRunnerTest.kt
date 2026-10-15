package com.example.integrityprobe

import java.security.Signature
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import org.junit.Assert.*
import org.junit.Test

class VendorSigningRunnerTest {
    private class FakeBackend : VendorKeyBackend {
        // Test fixture only; the production backend never uses DebugKeyGenerator.
        val material = DebugKeyGenerator().generate("EC", "Runner fixture", 1)
        val aliases = mutableSetOf<String>()
        var generated = 0
        var signed = 0
        var opened = false
        var lastChallenge: ByteArray? = null
        var lastInput: ByteArray? = null
        var installFailure: Throwable? = null
        var generationFailure: Exception? = null
        var signFailure: Exception? = null
        var invalidSignature = false
        var emptyChain = false
        override fun providers() = "Test provider listing"
        override fun install(): String {
            installFailure?.let { throw it }
            return "Test backend installed"
        }
        override fun open() { opened = true }
        override fun contains(alias: String) = alias in aliases
        override fun generate(alias: String, challenge: ByteArray) {
            check(alias !in aliases)
            generationFailure?.let { throw it }
            generated++
            lastChallenge = challenge.copyOf()
            aliases.add(alias)
        }
        override fun chain(alias: String): List<X509Certificate> = if (emptyChain) emptyList() else material.chain.toList()
        override fun sign(alias: String, bytes: ByteArray): ByteArray {
            signFailure?.let { throw it }
            signed++
            lastInput = bytes.copyOf()
            return Signature.getInstance(SigningText.ALGORITHM, BouncyCastleProvider()).run {
                initSign(material.keyPair.private)
                update(if (invalidSignature) byteArrayOf(1, 2, 3) else bytes)
                sign()
            }
        }
        override fun delete(alias: String) { aliases.remove(alias) }
    }

    @Test fun detectionDoesNotGenerateOrSign() {
        val backend = FakeBackend()
        val result = VendorSigningRunner(backend, "Test device").run(VendorAction.DETECT, VendorForm())
        assertTrue(result.log, result.success)
        assertTrue(backend.opened)
        assertEquals(0, backend.generated)
        assertEquals(0, backend.signed)
        assertNull(result.signatureBase64)
        assertTrue(result.log.contains("未生成密钥"))
    }

    @Test fun newKeyIsPersistentAndSignsExactCustomContent() {
        val backend = FakeBackend()
        val form = VendorForm(content = "  应用|udid|nonce\r\n ")
        val result = VendorSigningRunner(backend, "Test device").run(VendorAction.SIGN, form)
        assertTrue(result.log, result.success)
        assertEquals(1, backend.generated)
        assertTrue(form.alias in backend.aliases)
        assertArrayEquals(SigningText.utf8(form.challenge), backend.lastChallenge)
        assertArrayEquals(SigningText.utf8(form.content), backend.lastInput)
        assertEquals(form.content, result.input)
        assertEquals(2, result.certificates.size)
        assertEquals(backend.material.chainPem, result.chainPem)
        val verifier = Signature.getInstance(SigningText.ALGORITHM, BouncyCastleProvider())
        verifier.initVerify(backend.material.chain[0].publicKey)
        verifier.update(SigningText.utf8(form.content))
        assertTrue(verifier.verify(Base64.decode(result.signatureBase64)))
        assertTrue(result.report().contains(form.content))
    }

    @Test fun existingAliasIsNeverRegeneratedWhenChallengeChanges() {
        val backend = FakeBackend()
        val runner = VendorSigningRunner(backend, "Test")
        val form = VendorForm()
        assertTrue(runner.run(VendorAction.SIGN, form).success)
        val result = runner.run(VendorAction.SIGN, form.copy(challenge = "changed", content = "new request"))
        assertTrue(result.log, result.success)
        assertEquals(1, backend.generated)
        assertEquals(2, backend.signed)
        assertArrayEquals(SigningText.utf8(form.challenge), backend.lastChallenge)
        assertTrue(result.log.contains("本次输入的证明挑战未用于生成"))
    }

    @Test fun missingProviderReportsStageAndStopsWithoutFallback() {
        val backend = FakeBackend().apply { installFailure = ClassNotFoundException("vendor missing") }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.SIGN, VendorForm())
        assertFalse(result.success)
        assertFalse(backend.opened)
        assertEquals(0, backend.generated)
        assertTrue(result.log.contains("[失败] 加载并注册华为 Provider"))
        assertTrue(result.log.contains("ClassNotFoundException"))
        assertTrue(result.log.contains("未切换 AndroidKeyStore"))
    }

    @Test fun vendorLinkageErrorIsADiagnosticNotACrash() {
        val backend = FakeBackend().apply { installFailure = NoClassDefFoundError("missing vendor dependency") }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.DETECT, VendorForm())
        assertFalse(result.success)
        assertTrue(result.log.contains("NoClassDefFoundError"))
    }

    @Test fun signingFailurePreservesCertificatesAndCauseChain() {
        val backend = FakeBackend().apply {
            signFailure = IllegalStateException("sign failed", SecurityException("denied"))
        }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.SIGN, VendorForm())
        assertFalse(result.success)
        assertEquals(backend.material.chainPem, result.chainPem)
        assertNull(result.signatureBase64)
        assertTrue(result.log.contains("SecurityException: denied"))
        assertTrue(VendorForm().alias in backend.aliases)
    }

    @Test fun generationFailureIsNotRetriedThroughAnotherBackend() {
        val backend = FakeBackend().apply { generationFailure = IllegalArgumentException("Unsupported params") }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.SIGN, VendorForm())
        assertFalse(result.success)
        assertEquals(0, backend.signed)
        assertNull(result.chainPem)
        assertTrue(result.log.contains("[失败] 创建或复用 EC 密钥"))
    }

    @Test fun invalidSignatureIsNotPresentedAsUsableSign() {
        val backend = FakeBackend().apply { invalidSignature = true }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.SIGN, VendorForm())
        assertFalse(result.success)
        assertNull(result.signatureBase64)
        assertNull(result.signatureHex)
        assertNotNull(result.chainPem)
        assertTrue(result.log.contains("签名与叶证书公钥不匹配"))
    }

    @Test fun emptyChainStopsBeforeSigning() {
        val backend = FakeBackend().apply { emptyChain = true }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.SIGN, VendorForm())
        assertFalse(result.success)
        assertEquals(0, backend.signed)
        assertTrue(result.log.contains("设备未返回证书链"))
    }

    @Test fun deleteOnlyRemovesRequestedAliasAndDoesNotGenerate() {
        val backend = FakeBackend().apply { aliases.addAll(listOf("a", "b")) }
        val result = VendorSigningRunner(backend, "Test").run(VendorAction.DELETE, VendorForm(alias = "a"))
        assertTrue(result.log, result.success)
        assertEquals(setOf("b"), backend.aliases)
        assertEquals(0, backend.generated)
    }
}
