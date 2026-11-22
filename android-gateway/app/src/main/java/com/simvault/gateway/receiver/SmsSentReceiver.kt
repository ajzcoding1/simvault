package com.simvault.gateway.receiver

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import com.simvault.gateway.sms.SmsDispatchOutcome
import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class SmsSentReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_SMS_SENT) return
        val nonce = intent.getStringExtra(EXTRA_NONCE)?.takeIf { it.isNotBlank() } ?: return
        val tracker = trackers[nonce] ?: return

        val partOutcome = when (resultCode) {
            Activity.RESULT_OK -> null
            SmsManager.RESULT_ERROR_RADIO_OFF -> SmsDispatchOutcome.Failed("CARRIER_RADIO_OFF")
            SmsManager.RESULT_ERROR_NO_SERVICE -> SmsDispatchOutcome.Failed("NO_CARRIER_SERVICE")
            SmsManager.RESULT_ERROR_GENERIC_FAILURE -> SmsDispatchOutcome.Failed("SMS_GENERIC_FAILURE")
            SmsManager.RESULT_ERROR_NULL_PDU -> SmsDispatchOutcome.Failed("SMS_NULL_PDU")
            SmsManager.RESULT_ERROR_LIMIT_EXCEEDED -> SmsDispatchOutcome.Failed("SMS_LIMIT_EXCEEDED")
            SmsManager.RESULT_ERROR_FDN_CHECK_FAILURE -> SmsDispatchOutcome.Failed("FDN_CHECK_FAILURE")
            SmsManager.RESULT_ERROR_SHORT_CODE_NOT_ALLOWED -> SmsDispatchOutcome.Failed("SHORT_CODE_NOT_ALLOWED")
            SmsManager.RESULT_ERROR_SHORT_CODE_NEVER_ALLOWED -> SmsDispatchOutcome.Failed("SHORT_CODE_DENIED")
            else -> {
                val radioErr = intent.getIntExtra("errorCode", -1)
                if (radioErr >= 0) {
                    SmsDispatchOutcome.Failed("CARRIER_ERR_${resultCode}_$radioErr")
                } else {
                    SmsDispatchOutcome.DeliveryUnknown
                }
            }
        }

        if (partOutcome != null) {
            trackers.remove(nonce)
            tracker.deferred.complete(partOutcome)
            return
        }

        if (tracker.remainingParts.decrementAndGet() <= 0) {
            trackers.remove(nonce)
            tracker.deferred.complete(SmsDispatchOutcome.SentToNetwork)
        }
    }

    private data class PendingSentTracker(
        val remainingParts: AtomicInteger,
        val deferred: CompletableDeferred<SmsDispatchOutcome>
    )

    companion object {
        const val ACTION_SMS_SENT = "com.simvault.gateway.SMS_SENT"
        const val EXTRA_NONCE = "dispatch_nonce"
        const val EXTRA_PART_INDEX = "part_index"

        private val trackers = ConcurrentHashMap<String, PendingSentTracker>()

        fun registerTracker(
            nonce: String,
            totalParts: Int,
            deferred: CompletableDeferred<SmsDispatchOutcome>
        ) {
            trackers[nonce] = PendingSentTracker(AtomicInteger(totalParts.coerceAtLeast(1)), deferred)
        }

        fun unregisterTracker(nonce: String) {
            trackers.remove(nonce)
        }
    }
}
