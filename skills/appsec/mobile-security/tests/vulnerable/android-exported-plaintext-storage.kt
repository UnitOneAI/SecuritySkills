package com.example.vulnerable

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.util.Log

class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val refreshToken = intent.getStringExtra("refresh_token") ?: return
        val prefs = getSharedPreferences("auth", Context.MODE_PRIVATE)
        prefs.edit()
            .putString("refresh_token", refreshToken)
            .putString("session_owner", intent.getStringExtra("email"))
            .apply()

        Log.i("LoginActivity", "stored refresh_token=$refreshToken")
    }
}
