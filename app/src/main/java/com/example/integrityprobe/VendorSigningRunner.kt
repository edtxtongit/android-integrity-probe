package com.example.integrityprobe

import java.io.PrintWriter
import java.io.StringWriter
import java.security.Signature
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Backend abstraction allows orchestration tests without a phone or Android runtime. */
internal interface VendorKeyBackend {
    fun diagnostics(): String = ""
    fun providers(): String
    fun install(): String
    fun open()
    fun contains(alias: String): Boolean
    fun generate(alias: String, challenge: ByteArray)
    fun chain(alias: String): List<X509Certificate>
    fun sign(alias: String, bytes: ByteArray): ByteArray
    fun delete(alias: String)
}

internal enum class VendorAction(val title: String) {
    DETECT("探测接口"), SIGN("创建或复用并签名"), DELETE("删除测试密钥")
}

internal data class VendorForm(
    val alias: String = "probe_hw_service_ec",
    val challenge: String = "challenge_intelligent",
    val content: String = "com.example.app|test-udid|test-nonce"
)

internal data class VendorCertificate(val summary: String, val pem: String)

internal data class VendorSigningResult(
    val action: VendorAction,
    val alias: String,
    val success: Boolean,
    val log: String,
    val input: String? = null,
    val inputInfo: String? = null,
    val signatureBase64: String? = null,
    val signatureHex: String? = null,
    val publicKeyPem: String? = null,
    val certificates: List<VendorCertificate> = emptyList(),
    val chainPem: String? = null,
    val chainJson: String? = null
) {
    fun report(): String = buildString {
        appendLine("荣耀接口尝试 · ${action.title} · ${if (success) "PASS" else "FAIL"}")
        appendLine(log)
        if (input != null) {
            appendLine("\n--- 签名原文开始（UTF-8，保留空白）---")
            append(input)
            appendLine("\n--- 签名原文结束 ---")
        }
        inputInfo?.let { appendLine("\n$it") }
        signatureBase64?.let { appendLine("\nsign / ASN.1 DER ECDSA / Base64:\n$it") }
        signatureHex?.let { appendLine("\nsign / ASN.1 DER ECDSA / Hex:\n$it") }
        publicKeyPem?.let { appendLine("\n$it") }
        certificates.forEach { appendLine("\n${it.summary}") }
        chainPem?.let { appendLine("\n设备返回的证书链 PEM:\n$it") }
        chainJson?.let { appendLine("\n证书链 Base64 DER JSON 数组（字段封装需按服务协议确认）:\n$it") }
    }
}

/** No fallback to AndroidKeyStore, no automatic replacement/deletion of existing keys. */
internal class VendorSigningRunner(
    private val backend: VendorKeyBackend,
    private val environment: String
) {
    fun run(action: VendorAction, form: VendorForm): VendorSigningResult {
        val log = StringBuilder()
        var step = "初始化"
        var success = false
        var input: String? = null
        var inputInfo: String? = null
        var signatureBase64: String? = null
        var signatureHex: String? = null
        var publicKeyPem: String? = null
        var certificates: List<VendorCertificate> = emptyList()
        var chainPem: String? = null
        var chainJson: String? = null
        fun <T> stage(label: String, operation: () -> T): T {
            step = label
            log.appendLine("\n[开始] $label")
            return operation().also { log.appendLine("[成功] $label") }
        }
        fun failure(error: Throwable) {
            log.appendLine("[失败] $step")
            // Full cause chain is displayed/copied, never sent to logcat or a server.
            log.appendLine(StringWriter().also { error.printStackTrace(PrintWriter(it)) }.toString())
            log.appendLine("未切换 AndroidKeyStore，未使用软件密钥或本地调试 CA。")
            if (action == VendorAction.SIGN) {
                log.appendLine("未自动删除或重建 alias；若已产生条目，将保留供再次诊断。")
            }
        }
        log.appendLine(environment)
        log.appendLine("时间: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(Date())}")
        log.appendLine("操作: ${action.title}\nalias: ${form.alias}")
        log.appendLine("Provider FQCN: ${VendorProviderSelection.CLASS_NAME}\nKeyStore: ${VendorProviderSelection.STORE_TYPE}")
        log.appendLine("仅操作本 App 可访问的条目；不代表目标 App 的同名密钥。")
        try {
            if (action != VendorAction.DETECT) stage("校验输入") {
                require(form.alias.isNotBlank() && form.alias.length <= 100 && form.alias.none(Char::isISOControl)) {
                    "alias 需要 1–100 个字符，不能全空白或包含控制字符"
                }
                if (action == VendorAction.SIGN) {
                    SigningText.contentBytes(form.content)
                    SigningText.challengeBytes(form.challenge)
                }
            }
            stage("列出当前进程的 Provider") { log.appendLine(backend.providers()) }
            stage("加载并注册荣耀 Provider") { log.appendLine(backend.install()) }
            stage("打开 HwKeystore") { backend.open() }
            when (action) {
                VendorAction.DETECT -> log.appendLine("接口探测完成；未生成密钥，未验证 Attestation 或签名能力。")
                VendorAction.DELETE -> {
                    stage("删除指定 alias") {
                        if (backend.contains(form.alias)) {
                            backend.delete(form.alias)
                            check(!backend.contains(form.alias)) { "删除后 alias 仍然存在" }
                            log.appendLine("已删除 ${form.alias}；对应私钥不能恢复。")
                        } else log.appendLine("alias 不存在，无需删除。")
                    }
                }
                VendorAction.SIGN -> {
                    val bytes = SigningText.contentBytes(form.content)
                    input = form.content
                    inputInfo = "算法: ${SigningText.ALGORITHM}\n编码: UTF-8（不 trim、不添加换行、不做 Unicode 归一化）" +
                        "\n字节数: ${bytes.size}\n原文字节 SHA-256: ${SigningText.sha256(bytes)}" +
                        "\n原文字节 Base64: ${SigningText.base64(bytes)}\n原文字节 Hex: ${SigningText.hex(bytes)}"
                    stage("创建或复用 EC 密钥") {
                        if (backend.contains(form.alias)) {
                            log.appendLine("复用已有 alias；本次输入的证明挑战未用于生成，原证书与 challenge 不变。")
                        } else {
                            val challenge = SigningText.challengeBytes(form.challenge)
                            log.appendLine("新建密钥；请求的 attestation challenge (UTF-8/Base64): ${SigningText.base64(challenge)}")
                            backend.generate(form.alias, challenge)
                            log.appendLine("新密钥已生成并保留在 HwKeystore；私钥不导出。")
                        }
                    }
                    val chain = stage("读取同一 alias 的证书链") {
                        backend.chain(form.alias).also { check(it.isNotEmpty()) { "设备未返回证书链" } }
                    }
                    stage("导出公钥与证书材料") {
                        chainPem = chain.joinToString("") { SigningText.pem("CERTIFICATE", it.encoded) }
                        chainJson = SigningText.chainJson(chain)
                        publicKeyPem = SigningText.pem("PUBLIC KEY", chain.first().publicKey.encoded)
                        certificates = chain.mapIndexed { index, cert ->
                            VendorCertificate(SigningText.describe(cert, index), SigningText.pem("CERTIFICATE", cert.encoded))
                        }
                        log.appendLine("证书数: ${chain.size}；保留设备返回顺序。")
                        log.appendLine("链尾证书 SHA-256: ${SigningText.sha256(chain.last().encoded)}")
                        log.appendLine("链尾公钥 SPKI SHA-256: ${SigningText.sha256(chain.last().publicKey.encoded)}")
                        log.appendLine("链尾仅为返回链的最后一张，不自动视为可信根。")
                    }
                    stage("使用厂商私钥签名并以叶证书公钥验签") {
                        check(chain.first().publicKey.algorithm.equals("EC", ignoreCase = true)) {
                            "现有 alias 的叶证书不是 EC；请使用新的 alias，不会覆盖旧条目"
                        }
                        val signature = backend.sign(form.alias, bytes)
                        val verifier = Signature.getInstance(SigningText.ALGORITHM)
                        verifier.initVerify(chain.first().publicKey)
                        verifier.update(bytes)
                        check(verifier.verify(signature)) { "签名与叶证书公钥不匹配；不输出可提交的 sign" }
                        signatureBase64 = SigningText.base64(signature)
                        signatureHex = SigningText.hex(signature)
                        log.appendLine("本地验签: PASS；sign 为 ASN.1 DER 编码的 ECDSA 签名，不是裸 r||s。")
                    }
                    log.appendLine("成功仅指本地签名验签；未进行服务端验链、证明策略校验或 HTTP 请求。")
                }
            }
            success = true
        } catch (e: Exception) {
            failure(e)
        } catch (e: LinkageError) {
            // Missing/incompatible vendor framework dependencies are expected probe failures.
            failure(e)
        }
        backend.diagnostics().takeIf { it.isNotEmpty() }?.let { log.appendLine("\n实际 Provider 路径：\n$it") }
        return VendorSigningResult(action, form.alias, success, log.toString(), input, inputInfo,
            signatureBase64, signatureHex, publicKeyPem, certificates, chainPem, chainJson)
    }
}
