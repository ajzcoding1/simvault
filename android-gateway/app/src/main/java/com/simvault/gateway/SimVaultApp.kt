package com.simvault.gateway

import android.app.Application
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.service.GatewayForegroundService
import com.simvault.gateway.worker.GatewayPollWorker

class SimVaultApp : Application() {
    override fun onCreate() {
        super.onCreate()
        GatewayPollWorker.schedulePeriodic(this)
        val store = SecureCredentialStore(this)
        if (store.isEnrolled() && store.isBackgroundServiceEnabled()) {
            runCatching { GatewayForegroundService.start(this) }
        }
    }
}
