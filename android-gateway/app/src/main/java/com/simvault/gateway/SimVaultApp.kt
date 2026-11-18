package com.simvault.gateway

import android.app.Application
import com.simvault.gateway.worker.GatewayPollWorker

class SimVaultApp : Application() {
    override fun onCreate() {
        super.onCreate()
        GatewayPollWorker.schedulePeriodic(this)
    }
}
