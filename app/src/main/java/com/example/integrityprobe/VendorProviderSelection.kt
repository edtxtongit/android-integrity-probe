package com.example.integrityprobe

import java.security.Provider

/** FQCN confirmed by the user's HnMMS APK analysis; JCA names are discovered, not guessed. */
internal object VendorProviderSelection {
    const val CLASS_NAME = "com.hihonor.android.security.keystore.HwUniversalKeyStoreProvider"
    const val STORE_TYPE = "HwKeystore"

    fun requireRegistered(providers: Array<Provider>, className: String = CLASS_NAME): Provider {
        val matches = providers.filter { it.javaClass.name == className }
        check(matches.size == 1) {
            "需要且仅能有一个 $className 实例；匹配数量=${matches.size}。已注册: " +
                providers.joinToString { "${it.name} [${it.javaClass.name}]" }
        }
        return matches.single()
    }
}
