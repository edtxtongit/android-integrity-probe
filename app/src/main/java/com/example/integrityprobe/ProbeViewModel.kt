package com.example.integrityprobe

import android.app.Application
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class DebugOutput(
    val summary: String,
    val privateKey: String,
    val publicKey: String,
    val chain: String,
    val proof: String,
    val imported: DebugKeyImporter.ImportResult
) {
    fun fullReport() = listOf(summary, imported.detail, privateKey, publicKey, chain, proof).joinToString("\n\n")
}

internal data class ProbeUiState(
    val busy: String? = null,
    val error: String? = null,
    val probe: IntegrityProbe.ProbeReport? = null,
    val certificates: String? = null,
    val debug: DebugOutput? = null,
    val vendorForm: VendorForm = VendorForm(),
    val vendorResult: VendorSigningResult? = null
)

class ProbeViewModel(application: Application) : AndroidViewModel(application) {
    private val mutableState = MutableStateFlow(ProbeUiState())
    internal val state = mutableState.asStateFlow()

    fun runProbe() = work("正在检测设备能力…") {
        val report = IntegrityProbe(getApplication()).runProbe()
        mutableState.update { it.copy(probe = report) }
    }

    fun loadCertificates() = work("正在请求硬件证明证书…") {
        val report = IntegrityProbe(getApplication()).showCertificateChains()
        mutableState.update { it.copy(certificates = report) }
    }

    fun generate(algorithm: String, name: String, days: Int, strongBox: Boolean) {
        if (mutableState.value.busy != null) return
        mutableState.update { it.copy(debug = null) }
        work("正在生成密钥、签发调试证书并尝试导入…") {
            val material = DebugKeyGenerator().generate(algorithm, name, days)
            val imported = DebugKeyImporter.importAndVerify(material, strongBox)
            val output = DebugOutput(material.summary, material.privateKeyPem, material.publicKeyPem,
                material.chainPem, material.signingProof, imported)
            mutableState.update { it.copy(debug = output) }
        }
    }

    fun clearDebug() {
        if (mutableState.value.busy == null) mutableState.update { it.copy(debug = null, error = null) }
    }

    internal fun updateVendorForm(form: VendorForm) {
        if (mutableState.value.busy == null) mutableState.update { it.copy(vendorForm = form) }
    }

    internal fun runVendor(action: VendorAction, form: VendorForm) {
        if (mutableState.value.busy != null) return
        mutableState.update { it.copy(vendorResult = null) }
        work("荣耀接口：${action.title}…") {
            val environment = "设备: ${Build.MANUFACTURER} / ${Build.MODEL}\n" +
                "Android ${Build.VERSION.RELEASE} / API ${Build.VERSION.SDK_INT}\n" +
                "Build: ${Build.DISPLAY}\nProbe version: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})\nApp: ${getApplication<Application>().packageName} / targetSdk ${getApplication<Application>().applicationInfo.targetSdkVersion}"
            val result = VendorSigningRunner(HonorKeyBackend(), environment).run(action, form)
            mutableState.update { it.copy(vendorResult = result) }
        }
    }

    internal fun clearVendorResult() {
        if (mutableState.value.busy == null) mutableState.update { it.copy(vendorResult = null) }
    }

    fun dismissError() = mutableState.update { it.copy(error = null) }

    private fun work(label: String, block: () -> Unit) {
        if (mutableState.value.busy != null) return
        mutableState.update { it.copy(busy = label, error = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { block() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                mutableState.update { it.copy(error = "${e.javaClass.simpleName}: ${e.message ?: "操作失败，请重试"}") }
            } finally {
                mutableState.update { it.copy(busy = null) }
            }
        }
    }
}
