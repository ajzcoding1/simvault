package com.simvault.gateway.sms

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import androidx.core.content.ContextCompat
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.SimSubscriptionInfo
import com.simvault.gateway.receiver.SmsDeliveryReceiver
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

sealed class SmsDispatchOutcome {
    data object SentToNetwork : SmsDispatchOutcome()
    data class Failed(val errorCode: String) : SmsDispatchOutcome()
    data object DeliveryUnknown : SmsDispatchOutcome()
}

class NativeSmsSender(private val context: Context) {

    private val e164Regex = Regex("^\\+[1-9]\\d{6,14}$")

    fun hasSendSmsPermission(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) ==
            PackageManager.PERMISSION_GRANTED
    }

    fun hasReadPhoneStatePermission(): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) ==
            PackageManager.PERMISSION_GRANTED
    }

    @SuppressLint("MissingPermission")
    fun listActiveSims(): List<SimSubscriptionInfo> {
        if (!hasReadPhoneStatePermission()) return emptyList()
        val subManager = context.getSystemService(SubscriptionManager::class.java) ?: return emptyList()
        val activeList = subManager.activeSubscriptionInfoList ?: return emptyList()
        return activeList
            .sortedBy { it.simSlotIndex }
            .map { info ->
                val rawNumber = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    subManager.getPhoneNumber(info.subscriptionId)
                } else {
                    @Suppress("DEPRECATION")
                    info.number ?: ""
                }
                SimSubscriptionInfo(
                    subscriptionId = info.subscriptionId,
                    slotIndex = info.simSlotIndex,
                    carrierLabel = info.carrierName?.toString()?.takeIf { it.isNotBlank() }
                        ?: "SIM ${info.simSlotIndex + 1}",
                    maskedMsisdn = if (rawNumber.isNotBlank()) LocalJobJournal.maskE164(rawNumber) else "Number hidden by SIM"
                )
            }
    }

    private fun resolveSmsManager(subscriptionId: Int): SmsManager? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(SmsManager::class.java)
                ?.createForSubscriptionId(subscriptionId)
        } else {
            @Suppress("DEPRECATION")
            SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    suspend fun sendSms(
        jobId: String,
        toE164: String,
        body: String,
        simSlot: Int,
        mockMode: Boolean
    ): SmsDispatchOutcome {
        if (!e164Regex.matches(toE164.trim())) {
            return SmsDispatchOutcome.Failed("INVALID_E164_RECIPIENT")
        }
        if (body.isBlank()) {
            return SmsDispatchOutcome.Failed("EMPTY_SMS_BODY")
        }
        if (mockMode) {
            return SmsDispatchOutcome.SentToNetwork
        }
        if (!hasSendSmsPermission()) {
            return SmsDispatchOutcome.Failed("MISSING_SEND_SMS_PERMISSION")
        }

        val activeSims = listActiveSims()
        val targetSim = activeSims.firstOrNull { it.slotIndex == simSlot }
            ?: activeSims.firstOrNull()
            ?: return SmsDispatchOutcome.Failed("SIM_SLOT_UNAVAILABLE")

        val smsManager = resolveSmsManager(targetSim.subscriptionId)
            ?: return SmsDispatchOutcome.Failed("SMS_MANAGER_UNAVAILABLE")

        val parts = smsManager.divideMessage(body)
        if (parts.isEmpty()) {
            return SmsDispatchOutcome.Failed("EMPTY_SMS_BODY")
        }

        val nonce = UUID.randomUUID().toString()
        val actionSent = "com.simvault.gateway.SMS_SENT.$jobId.$nonce"
        val remainingParts = AtomicInteger(parts.size)
        val resultDeferred = CompletableDeferred<SmsDispatchOutcome>()

        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
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
                    else -> SmsDispatchOutcome.DeliveryUnknown
                }
                if (partOutcome != null) {
                    resultDeferred.complete(partOutcome)
                    return
                }
                if (remainingParts.decrementAndGet() <= 0) {
                    resultDeferred.complete(SmsDispatchOutcome.SentToNetwork)
                }
            }
        }

        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, IntentFilter(actionSent), Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, IntentFilter(actionSent))
        }

        return try {
            val sentIntents = ArrayList<PendingIntent>(parts.size)
            val deliveryIntents = ArrayList<PendingIntent>(parts.size)
            for (index in parts.indices) {
                val sentIntent = Intent(actionSent).setPackage(context.packageName)
                sentIntents.add(
                    PendingIntent.getBroadcast(
                        context,
                        (jobId + "_" + nonce + "_sent_$index").hashCode(),
                        sentIntent,
                        flags
                    )
                )
                val deliveryIntent = Intent(context, SmsDeliveryReceiver::class.java).apply {
                    setPackage(context.packageName)
                    action = SmsDeliveryReceiver.ACTION_SMS_DELIVERED
                    putExtra(SmsDeliveryReceiver.EXTRA_JOB_ID, jobId)
                    putExtra(SmsDeliveryReceiver.EXTRA_NONCE, nonce)
                }
                deliveryIntents.add(
                    PendingIntent.getBroadcast(
                        context,
                        (jobId + "_" + nonce + "_dlr_$index").hashCode(),
                        deliveryIntent,
                        flags
                    )
                )
            }

            if (parts.size > 1) {
                smsManager.sendMultipartTextMessage(toE164.trim(), null, parts, sentIntents, deliveryIntents)
            } else {
                smsManager.sendTextMessage(toE164.trim(), null, body, sentIntents[0], deliveryIntents[0])
            }
            withTimeoutOrNull(25_000L) { resultDeferred.await() } ?: SmsDispatchOutcome.DeliveryUnknown
        } catch (_: SecurityException) {
            SmsDispatchOutcome.Failed("PERMISSION_REVOKED")
        } catch (_: Exception) {
            SmsDispatchOutcome.DeliveryUnknown
        } finally {
            runCatching { context.unregisterReceiver(receiver) }
        }
    }
}
