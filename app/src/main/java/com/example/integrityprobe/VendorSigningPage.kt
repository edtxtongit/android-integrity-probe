package com.example.integrityprobe

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun VendorSigningPage(
    form: VendorForm,
    running: Boolean,
    result: VendorSigningResult?,
    onFormChange: (VendorForm) -> Unit,
    onRun: (VendorAction, VendorForm) -> Unit,
    onClearResult: () -> Unit,
    copy: (String, String, Boolean) -> Unit
) {
    var deleteAlias by remember { mutableStateOf<String?>(null) }
    val aliasValid = form.alias.isNotBlank() && form.alias.length <= 100 && form.alias.none(Char::isISOControl)
    val challengeBytes = remember(form.challenge) { runCatching { SigningText.challengeBytes(form.challenge) }.getOrNull() }
    val contentBytes = remember(form.content) { runCatching { SigningText.contentBytes(form.content) }.getOrNull() }
    val plainKeyboard = KeyboardOptions(capitalization = KeyboardCapitalization.None,
        autoCorrectEnabled = false, keyboardType = KeyboardType.Text)

    PageHeading("华为接口尝试", "荣耀 400 / Android 15 · 在普通 App 内验证，不预设设备支持。")
    Notice("私钥留在 Keystore，直接调用签名", "仅尝试 HwUniversalKeyStoreProvider / HwKeystore。失败不会切换到 AndroidKeyStore，也不使用软件实验页的自签证书。")
    OutlinedButton(onClick = { onRun(VendorAction.DETECT, form) }, enabled = !running,
        modifier = Modifier.fillMaxWidth()) { Text("仅探测 Provider 与接口") }

    Card(shape = RoundedCornerShape(24.dp)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("密钥与请求", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            OutlinedTextField(value = form.alias,
                onValueChange = { if (it.length <= 100) onFormChange(form.copy(alias = it)) },
                label = { Text("Keystore alias") }, supportingText = { Text("仅访问本 App 的条目；存在则复用，不自动覆盖") },
                isError = !aliasValid, enabled = !running, singleLine = true,
                keyboardOptions = plainKeyboard, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = form.challenge,
                onValueChange = { if (it.length <= 128) onFormChange(form.copy(challenge = it)) },
                label = { Text("生成时的证明挑战（UTF-8 文本）") },
                supportingText = { Text("1–128 字节。当前 ${challengeBytes?.size ?: "无效"} 字节；与请求 nonce 分开") },
                isError = challengeBytes == null, enabled = !running, singleLine = true,
                keyboardOptions = plainKeyboard, modifier = Modifier.fillMaxWidth())
            Text("challenge_intelligent 只是可修改的预填文本。复用 alias 时，此输入不会改变原证书；要更新证明挑战，请换一个 alias，或确认删除后再创建。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            HorizontalDivider()
            Text("SHA256withECDSA · EC P-256", style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary)
            OutlinedTextField(value = form.content,
                onValueChange = { if (it.length <= 16384) onFormChange(form.copy(content = it)) },
                label = { Text("自定义签名原文") },
                supportingText = { Text("UTF-8 · ${contentBytes?.size ?: "无效"} 字节 · 最多 16384 个 UTF-16 单元 / 65536 字节") },
                isError = contentBytes == null, enabled = !running, minLines = 4, maxLines = 8,
                keyboardOptions = plainKeyboard, modifier = Modifier.fillMaxWidth())
            Text("可输入 x-app-pkg|x-origin-udid|x-request-nonce 的实际值，也可签任意文本。严格保留空格、换行与分隔符，不 trim、不预先哈希；空文本也可签名。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = { onRun(VendorAction.SIGN, form) },
                enabled = !running && aliasValid && challengeBytes != null && contentBytes != null,
                modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.PlayArrow, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("创建 / 复用密钥并签名")
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CopyButton("复制输入原文") { copy("输入原文", form.content, false) }
                TextButton(onClick = { deleteAlias = form.alias }, enabled = !running && aliasValid) {
                    Text("删除此 alias", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
    if (result == null) {
        EmptyPanel(Icons.Outlined.VpnKey, "先探测接口，或直接尝试签名", "结果包含分步诊断、设备返回的证书链、Base64 / Hex 签名及本地验签结果。所有操作在本 App 自己的访问范围内进行。")
    } else {
        val title = if (!result.success) "${result.action.title}失败，可复制诊断报告"
            else when (result.action) {
                VendorAction.DETECT -> "接口可打开，尚未验证密钥证明能力"
                VendorAction.SIGN -> "签名完成，叶证书公钥本地验签通过"
                VendorAction.DELETE -> "测试密钥删除操作完成"
            }
        Notice(title, "下方是上一次操作的快照（alias：${result.alias}），修改输入不会改写旧结果。未进行服务端验链或发起 HTTP 请求。", warning = !result.success)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CopyButton("复制完整接口报告") { copy("接口签名完整报告", result.report(), false) }
            TextButton(onClick = onClearResult, enabled = !running) { Text("清除显示结果") }
        }
        Text("清除显示结果不删除 Keystore 密钥。报告可能含设备或应用标识、请求内容，分享前请检查。",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutputCard("分步诊断", "PROVIDER / HWKEYSTORE / 异常原因链", result.log, copy = copy)
        result.signatureBase64?.let {
            OutputCard("sign · Base64", "SHA256withECDSA · ASN.1 DER · 标准 Base64，有填充、无换行", it, copy = copy)
        }
        result.signatureHex?.let {
            OutputCard("sign · Hex", "同一签名的十六进制；不是固定 64 字节 r||s 编码", it, copy = copy)
        }
        result.input?.let { OutputCard("本次签名原文", "实际操作快照 · UTF-8", it, copy = copy) }
        result.inputInfo?.let { OutputCard("签名字节详情", "字节数 / SHA-256 / BASE64 / HEX", it, copy = copy) }
        result.chainPem?.let {
            OutputCard("设备证书链 PEM", "设备原始顺序 · 非软件实验页的自签链", it, copy = copy)
        }
        result.chainJson?.let {
            OutputCard("证书链 JSON 数组", "每项为 BASE64 DER；cerChain 的最终封装需按服务协议确认", it, copy = copy)
        }
        result.publicKeyPem?.let { OutputCard("叶证书公钥", "SubjectPublicKeyInfo · PEM", it, copy = copy) }
        result.certificates.forEachIndexed { index, certificate ->
            OutputCard("证书 $index 详情", "SUBJECT / ISSUER / 指纹 / 扩展", certificate.summary, copy = copy)
            CopyButton("仅复制证书 $index PEM") { copy("证书 $index PEM", certificate.pem, false) }
        }
    }
    deleteAlias?.let { alias ->
        AlertDialog(onDismissRequest = { deleteAlias = null }, title = { Text("删除此 App 下的密钥？") },
            text = { Text("将删除 HwKeystore 中的 $alias 及其关联证书。私钥不能恢复，旧证书对应的请求将不能再签名。其他 App 的同名条目不在本次操作范围内。") },
            confirmButton = {
                TextButton(enabled = !running, onClick = {
                    deleteAlias = null
                    onRun(VendorAction.DELETE, form.copy(alias = alias))
                }) { Text("确认删除") }
            }, dismissButton = { TextButton(onClick = { deleteAlias = null }) { Text("取消") } })
    }
}
