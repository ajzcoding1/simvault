package com.simvault.gateway.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.worker.GatewayPollWorker

class BootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        GatewayPollWorker.schedulePeriodic(context)
        if (SecureCredentialStore(context).isEnrolled()) {
            GatewayPollWorker.triggerImmediatePoll(context)
        }
    }
}
