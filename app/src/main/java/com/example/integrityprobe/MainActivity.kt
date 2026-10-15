package com.example.integrityprobe

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ProbeTheme {
                val model: ProbeViewModel = viewModel()
                val state by model.state.collectAsStateWithLifecycle()
                // Private key previews must not leak through screenshots or the recent-apps thumbnail.
                DisposableEffect(state.debug != null || state.busy != null) {
                    if (state.debug != null || state.busy != null) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                    onDispose { }
                }
                ProbeApp(state, model)
            }
        }
    }
}

@Composable
internal fun ProbeTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) darkColorScheme(
        primary = Color(0xFF76D8C2), onPrimary = Color(0xFF00382D),
        primaryContainer = Color(0xFF124D40), onPrimaryContainer = Color(0xFFABF2DB),
        background = Color(0xFF101815), surface = Color(0xFF16201C)
    ) else lightColorScheme(
        primary = Color(0xFF176B55), onPrimary = Color.White,
        primaryContainer = Color(0xFFD9F1E6), onPrimaryContainer = Color(0xFF0D4938),
        background = Color(0xFFF4F7F5), surface = Color(0xFFFCFDFC),
        secondaryContainer = Color(0xFFE6EDE8)
    )
    MaterialTheme(colorScheme = colors, typography = Typography(), content = content)
}

private data class Page(val name: String, val icon: ImageVector)
private val pages = listOf(
    Page("设备检测", Icons.Outlined.VerifiedUser),
    Page("接口签名", Icons.Outlined.VpnKey),
    Page("硬件证书", Icons.Outlined.Description),
    Page("软件实验", Icons.Outlined.Science)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProbeApp(state: ProbeUiState, model: ProbeViewModel) {
    var page by rememberSaveable { mutableIntStateOf(1) }
    val pageState = rememberSaveableStateHolder()
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    // Intentionally not rememberSaveable: never serialize key material into saved instance state.
    var pendingPrivateCopy by remember { mutableStateOf<Pair<String, String>?>(null) }
    val copy: (String, String, Boolean) -> Unit = { label, text, sensitive ->
        if (sensitive) pendingPrivateCopy = label to text
        else {
            copyText(context, label, text, false)
            scope.launch { snackbar.showSnackbar("已复制：$label") }
        }
    }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Integrity Probe", fontWeight = FontWeight.Bold, fontSize = 21.sp)
                        Text("ANDROID · 开发者调试台", style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                navigationIcon = {
                    Icon(Icons.Outlined.Security, contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(16.dp))
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        },
        bottomBar = {
            NavigationBar {
                pages.forEachIndexed { index, item ->
                    NavigationBarItem(selected = page == index, onClick = { page = index },
                        icon = { Icon(item.icon, contentDescription = null) }, label = { Text(item.name) })
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.TopCenter) {
            pageState.SaveableStateProvider(page) {
                Column(Modifier.widthIn(max = 840.dp).fillMaxSize()
                    .verticalScroll(rememberScrollState()).padding(horizontal = 20.dp, vertical = 12.dp)
                    .imePadding(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    if (state.busy != null) {
                        LinearProgressIndicator(Modifier.fillMaxWidth())
                        Text(state.busy, style = MaterialTheme.typography.bodySmall)
                    }
                    state.error?.let { error ->
                        Notice("操作未完成", error, warning = true)
                        TextButton(onClick = model::dismissError) { Text("关闭错误提示") }
                    }
                    when (page) {
                        0 -> ProbePage(state, model::runProbe, copy)
                        1 -> VendorSigningPage(state.vendorForm, state.busy != null, state.vendorResult,
                            model::updateVendorForm, model::runVendor, model::clearVendorResult, copy)
                        2 -> CertificatePage(state, model::loadCertificates, copy)
                        else -> DebugPage(state, model, copy)
                    }
                    Spacer(Modifier.height(8.dp))
                    Text("LOCAL DEBUG ONLY  /  本地结果不等于可信证明",
                        style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
    pendingPrivateCopy?.let { (label, text) ->
        AlertDialog(
            onDismissRequest = { pendingPrivateCopy = null },
            icon = { Icon(Icons.Outlined.Key, null) },
            title = { Text("复制内容包含私钥") },
            text = { Text("私钥将以明文放入系统剪贴板，可能被其他应用或剪贴板同步功能读取。仅使用测试密钥，调试后请清理剪贴板。") },
            confirmButton = {
                TextButton(onClick = {
                    copyText(context, label, text, true)
                    pendingPrivateCopy = null
                    scope.launch { snackbar.showSnackbar("已复制敏感调试材料") }
                }) { Text("仍然复制") }
            },
            dismissButton = { TextButton(onClick = { pendingPrivateCopy = null }) { Text("取消") } }
        )
    }
}

@Composable
private fun ProbePage(state: ProbeUiState, run: () -> Unit, copy: (String, String, Boolean) -> Unit) {
    PageHeading("设备完整性", "一次检测，了解设备的硬件安全与生态能力。")
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        shape = RoundedCornerShape(24.dp)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("DEVICE OVERVIEW", style = MaterialTheme.typography.labelMedium)
            SelectionContainer {
                Column {
                    Text("${Build.BRAND} ${Build.MODEL}", style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.SemiBold)
                    Text("Android ${Build.VERSION.RELEASE}  ·  API ${Build.VERSION.SDK_INT}",
                        style = MaterialTheme.typography.bodyMedium)
                }
            }
            Button(onClick = run, enabled = state.busy == null, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.PlayArrow, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(if (state.probe == null) "开始检测 · 12 项能力" else "重新检测")
            }
        }
    }
    Notice("信任边界", "本机检测仅供调试。生产环境必须使用服务端随机 challenge，并由服务端验签、验证证书链。")
    val report = state.probe
    if (report == null) {
        EmptyPanel(Icons.Outlined.FactCheck, "准备好开始检测", "包含 StrongBox、TEE、启动状态、Play Integrity 与 mTLS 等 12 项能力。")
    } else {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("PASS", "PARTIAL", "FAIL").forEach { status ->
                Surface(Modifier.weight(1f), shape = RoundedCornerShape(16.dp),
                    color = MaterialTheme.colorScheme.surface) {
                    Column(Modifier.padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(report.results.count { it.status == status }.toString(),
                            style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                        StatusBadge(status)
                    }
                }
            }
        }
        Text("PASS 本地操作成功 · PARTIAL 能力或配置不完整 · FAIL 不支持或操作失败",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        CopyButton("复制检测报告") { copy("检测报告", report.text, false) }
        report.results.forEachIndexed { index, result ->
            Card(shape = RoundedCornerShape(20.dp)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("%02d".format(index + 1), color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        StatusBadge(result.status)
                    }
                    SelectionContainer {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(result.name, fontWeight = FontWeight.SemiBold)
                            Text(result.detail, style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    CopyButton("复制此项") { copy(result.name, "${result.name}\n${result.status}\n${result.detail}", false) }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DebugPage(state: ProbeUiState, model: ProbeViewModel, copy: (String, String, Boolean) -> Unit) {
    var algorithm by rememberSaveable { mutableStateOf("EC") }
    var strongBox by rememberSaveable { mutableStateOf(false) }
    var commonName by rememberSaveable { mutableStateOf("Integrity Probe Debug") }
    var validity by rememberSaveable { mutableStateOf("30") }
    val days = validity.toIntOrNull()
    val validName = commonName.trim().let { it.isNotEmpty() && it.length <= 64 && it.none(Char::isISOControl) }
    val validDays = days != null && days in 1..3650
    val enabled = state.busy == null
    PageHeading("密钥实验室", "随机生成 → 导入 Keystore → 签名与验签")
    Notice("可导出，是因为先在 App 内生成", "下方私钥是导入前的软件原始密钥。即使导入了安全硬件，也不能证明私钥从未离开硬件。证书链由本地调试 CA 签发，不是 Android 硬件证明。", warning = true)
    Card(shape = RoundedCornerShape(24.dp)) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("生成配置", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text("密钥算法", style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = algorithm == "EC", onClick = { algorithm = "EC" },
                    enabled = enabled, label = { Text("EC · P-256") })
                FilterChip(selected = algorithm == "RSA", onClick = { algorithm = "RSA" },
                    enabled = enabled, label = { Text("RSA · 2048") })
            }
            OutlinedTextField(value = commonName, onValueChange = { commonName = it },
                modifier = Modifier.fillMaxWidth(), label = { Text("证书名称 / Common Name") },
                supportingText = { Text("1–64 个可见字符") }, isError = !validName,
                singleLine = true, enabled = enabled)
            OutlinedTextField(value = validity, onValueChange = { validity = it },
                modifier = Modifier.fillMaxWidth(), label = { Text("证书有效期（天）") },
                supportingText = { Text("1–3650 天，仅用于调试证书") }, isError = !validDays,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true, enabled = enabled)
            Text("导入目标", style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = !strongBox, onClick = { strongBox = false }, enabled = enabled,
                    label = { Text("Android Keystore") })
                FilterChip(selected = strongBox, onClick = { strongBox = true }, enabled = enabled,
                    label = { Text("请求 StrongBox") })
            }
            Text("不保证默认目标为 TEE；以实际存储级别为准。StrongBox 不支持时会报错，不自动降级。导入测试完成后自动删除临时条目。",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(onClick = { model.generate(algorithm, commonName, days ?: 30, strongBox) },
                enabled = enabled && validName && validDays, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Outlined.Refresh, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(if (state.debug == null) "随机生成并导入" else "重新生成并导入")
            }
        }
    }
    val output = state.debug
    if (output == null) {
        EmptyPanel(Icons.Outlined.VpnKey, "调试材料将在此显示", "包含 PKCS#8 私钥、公钥、叶证书及本地 CA 证书链，以及 Keystore 导入和验签结果。")
    } else {
        Notice(if (!output.imported.success) "导入或验证失败，生成材料已保留"
            else if (output.imported.hardwareBacked) "已导入安全硬件并通过本地验签"
            else "已导入 Keystore，未确认硬件存储",
            "私钥明文仅保存在当前会话内存中，不写入文件或日志。重新生成会替换旧材料；退出进程后不恢复。",
            warning = !output.imported.success || !output.imported.hardwareBacked)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CopyButton("复制全部调试材料") { copy("全部调试材料", output.fullReport(), true) }
            TextButton(onClick = model::clearDebug, enabled = enabled) { Text("清除调试材料") }
        }
        OutputCard("导入与硬件级别", "IMPORT RESULT", output.imported.detail, copy = copy)
        OutputCard("私钥", "PKCS#8 · 导入前的原始私钥", output.privateKey, sensitive = true, copy = copy)
        OutputCard("公钥", "X.509 / SubjectPublicKeyInfo", output.publicKey, copy = copy)
        OutputCard("对应的调试证书链", "PEM · 叶证书 → 本地 CA", output.chain, copy = copy)
        OutputCard("证书详情", "SUBJECT / ISSUER / SHA-256", output.summary, copy = copy)
        OutputCard("本地签名测试", "随机 CHALLENGE · 非服务端证明", output.proof, copy = copy)
    }
}

@Composable
private fun CertificatePage(state: ProbeUiState, run: () -> Unit, copy: (String, String, Boolean) -> Unit) {
    PageHeading("硬件证明证书", "与软件生成、导入的调试密钥相互独立。")
    Notice("在 Keystore 内重新生成密钥", "分别请求 TEE / StrongBox Attestation。此路径的私钥无法显示或导出；证书由设备返回，仍需服务端验证其信任链、challenge 与安全级别。")
    Button(onClick = run, enabled = state.busy == null, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Outlined.Description, null, Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text(if (state.certificates == null) "生成并查看硬件证书链" else "重新获取硬件证书链")
    }
    if (state.certificates == null) {
        EmptyPanel(Icons.Outlined.Description, "查看真实设备的证明材料", "展示证明字段、证书指纹与完整 PEM。系统不支持、配额限制或生成失败时会显示具体原因。")
    } else {
        OutputCard("硬件证书链报告", "TEE / STRONGBOX · 摘要与 PEM", state.certificates, copy = copy)
    }
}

@Composable
internal fun PageHeading(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
internal fun Notice(title: String, text: String, warning: Boolean = false) {
    Surface(shape = RoundedCornerShape(18.dp), color = if (warning) MaterialTheme.colorScheme.tertiaryContainer
        else MaterialTheme.colorScheme.secondaryContainer) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(if (warning) Icons.Outlined.WarningAmber else Icons.Outlined.Info, null, Modifier.size(20.dp))
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Text(text, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
internal fun EmptyPanel(icon: ImageVector, title: String, body: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 24.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Icon(icon, null, Modifier.size(36.dp), tint = MaterialTheme.colorScheme.primary)
        Text(title, style = MaterialTheme.typography.titleMedium)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun StatusBadge(status: String) {
    val colors = MaterialTheme.colorScheme
    Surface(shape = RoundedCornerShape(8.dp), color = when (status) {
        "PASS" -> colors.primaryContainer
        "FAIL" -> colors.errorContainer
        else -> colors.tertiaryContainer
    }) {
        Text(status, modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
    }
}

@Composable
internal fun OutputCard(title: String, subtitle: String, text: String, sensitive: Boolean = false,
    copy: (String, String, Boolean) -> Unit) {
    Card(shape = RoundedCornerShape(20.dp)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            CopyButton("复制$title") { copy(title, text, sensitive) }
            if (sensitive) {
                Text("明文测试私钥 · 请勿用于生产", color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelMedium)
            }
            SelectionContainer {
                Text(text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
internal fun CopyButton(label: String, onClick: () -> Unit) {
    TextButton(onClick = onClick) {
        Icon(Icons.Outlined.ContentCopy, null, Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(label)
    }
}

internal fun copyText(context: Context, label: String, text: String, sensitive: Boolean) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(label, text)
    if (sensitive && Build.VERSION.SDK_INT >= 24) {
        clip.description.extras = PersistableBundle().apply {
            // Android 13+ hides the preview when this compatibility key is set.
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    clipboard.setPrimaryClip(clip)
}
