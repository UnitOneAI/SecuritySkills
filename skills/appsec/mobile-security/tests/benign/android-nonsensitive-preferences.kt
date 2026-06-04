package com.example.safe

import android.content.Context

class SettingsStore(private val context: Context, private val tokenVault: TokenVault) {
    fun saveTheme(theme: String) {
        context.getSharedPreferences("ui", Context.MODE_PRIVATE)
            .edit()
            .putString("theme", theme)
            .apply()
    }

    fun saveRefreshToken(refreshToken: String) {
        tokenVault.storeRefreshToken(refreshToken)
    }
}

interface TokenVault {
    fun storeRefreshToken(refreshToken: String)
}
