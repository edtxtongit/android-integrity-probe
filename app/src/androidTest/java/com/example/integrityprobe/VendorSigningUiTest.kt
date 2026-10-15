package com.example.integrityprobe

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VendorSigningUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun customSigningTextIsPassedWithoutTrimming() {
        var submitted: VendorForm? = null
        var action: VendorAction? = null
        val text = "  自定义|udid|nonce\n "
        compose.setContent {
            var form by remember { mutableStateOf(VendorForm()) }
            ProbeTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    VendorSigningPage(form, false, null, { form = it }, { selected, snapshot ->
                        action = selected
                        submitted = snapshot
                    }, {}, { _, _, _ -> })
                }
            }
        }
        compose.onNodeWithText("自定义签名原文").performScrollTo().performTextReplacement(text)
        compose.onNodeWithText("创建 / 复用密钥并签名").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(VendorAction.SIGN, action)
            assertEquals(text, submitted!!.content)
        }
    }

    @Test fun deletionRequiresExplicitConfirmation() {
        var deletes = 0
        compose.setContent {
            ProbeTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    VendorSigningPage(VendorForm(), false, null, {}, { action, _ ->
                        if (action == VendorAction.DELETE) deletes++
                    }, {}, { _, _, _ -> })
                }
            }
        }
        compose.onNodeWithText("删除此 alias").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(0, deletes) }
        compose.onNodeWithText("取消").performClick()
        compose.runOnIdle { assertEquals(0, deletes) }
        compose.onNodeWithText("删除此 alias").performScrollTo().performClick()
        compose.onNodeWithText("确认删除").performClick()
        compose.runOnIdle { assertEquals(1, deletes) }
    }

    @Test fun copySignReturnsOnlySignatureAndFullReportIncludesDiagnostics() {
        val signature = "dGVzdC1zaWduYXR1cmU="
        val result = VendorSigningResult(VendorAction.SIGN, "fixture", true, "diagnostic fixture",
            input = "  payload\n", signatureBase64 = signature)
        var copied: String? = null
        compose.setContent {
            ProbeTheme {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    VendorSigningPage(VendorForm(), false, result, {}, { _, _ -> }, {}, { _, text, _ -> copied = text })
                }
            }
        }
        compose.onNodeWithText("复制sign · Base64").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(signature, copied) }
        compose.onNodeWithText("复制完整接口报告").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(result.report(), copied)
            assertTrue(copied!!.contains("diagnostic fixture"))
            assertTrue(copied!!.contains("  payload\n"))
        }
    }
}
