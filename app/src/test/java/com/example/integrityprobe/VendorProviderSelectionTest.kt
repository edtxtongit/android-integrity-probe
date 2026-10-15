package com.example.integrityprobe

import java.security.Provider
import org.junit.Assert.*
import org.junit.Test

class VendorProviderSelectionTest {
    @Suppress("DEPRECATION")
    private class TargetProvider(name: String) : Provider(name, 1.0, "Test fixture")
    @Suppress("DEPRECATION")
    private class OtherProvider(name: String) : Provider(name, 1.0, "Other fixture")

    @Test fun selectedByExactImplementationClassNotAssumedJcaName() {
        val target = TargetProvider("DifferentRuntimeName")
        val other = OtherProvider("HwUniversalKeyStoreProvider")
        assertSame(target, VendorProviderSelection.requireRegistered(arrayOf(other, target), TargetProvider::class.java.name))
    }

    @Test fun sameJcaNameDoesNotMakeAnUnrelatedProviderAcceptable() {
        val other = OtherProvider("HwUniversalKeyStoreProvider")
        assertThrows(IllegalStateException::class.java) {
            VendorProviderSelection.requireRegistered(arrayOf(other), TargetProvider::class.java.name)
        }
    }

    @Test fun ambiguousRegistrationsAreRejected() {
        assertThrows(IllegalStateException::class.java) {
            VendorProviderSelection.requireRegistered(arrayOf(TargetProvider("a"), TargetProvider("b")), TargetProvider::class.java.name)
        }
    }

    @Test fun profileUsesFqcnConfirmedByTargetApk() {
        assertEquals("com.hihonor.android.security.keystore.HwUniversalKeyStoreProvider", VendorProviderSelection.CLASS_NAME)
        assertEquals("HwKeystore", VendorProviderSelection.STORE_TYPE)
    }
}
