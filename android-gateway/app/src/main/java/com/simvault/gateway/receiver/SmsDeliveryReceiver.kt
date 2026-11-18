package com.simvault.gateway.receiver

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.worker.DeliveryReportWorker

class SmsDeliveryReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_SMS_DELIVERED) return
        val jobId = intent.getStringExtra(EXTRA_JOB_ID)?.takeIf { it.isNotBlank() } ?: return
        if (resultCode == Activity.RESULT_OK) {
            LocalJobJournal(context).updateDeliveryReceipt(jobId)
            DeliveryReportWorker.enqueue(context, jobId)
        }
    }

    companion object {
        const val ACTION_SMS_DELIVERED = "com.simvault.gateway.SMS_DELIVERED"
        const val EXTRA_JOB_ID = "job_id"
        const val EXTRA_NONCE = "dispatch_nonce"
    }
}
