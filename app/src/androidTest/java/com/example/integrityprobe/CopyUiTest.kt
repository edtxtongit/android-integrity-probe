package com.example.integrityprobe

import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CopyUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun copyButtonCopiesCompleteMultilineTextWithoutTruncation() {
        val text = "-----BEGIN CERTIFICATE-----\n" + "ABCDEFGHIJKL\n".repeat(60) + "-----END CERTIFICATE-----\n"
        lateinit var context: Context
        compose.setContent {
            context = LocalContext.current
            ProbeTheme {
                OutputCard("证书链", "PEM", text) { label, value, sensitive ->
                    copyText(context, label, value, sensitive)
                }
            }
        }
        compose.onNodeWithText("复制证书链").performClick()
        compose.runOnIdle {
            val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            assertEquals(text, manager.primaryClip!!.getItemAt(0).text.toString())
        }
    }

    @Test fun privateCopyIsMarkedSensitive() {
        lateinit var context: Context
        var requestedSensitive = false
        compose.setContent {
            context = LocalContext.current
            ProbeTheme {
                OutputCard("私钥", "PKCS#8", "test-only", sensitive = true) { label, value, sensitive ->
                    requestedSensitive = sensitive
                    copyText(context, label, value, sensitive)
                }
            }
        }
        compose.onNodeWithText("复制私钥").performClick()
        compose.runOnIdle {
            assertTrue(requestedSensitive)
            val clip = (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).primaryClip!!
            if (Build.VERSION.SDK_INT >= 24) assertTrue(clip.description.extras!!.getBoolean("android.content.extra.IS_SENSITIVE"))
        }
    }
}
