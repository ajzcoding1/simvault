package com.simvault.gateway.sms

import android.Manifest
import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SmsManager
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.SimSubscriptionInfo
import com.simvault.gateway.receiver.SmsDeliveryReceiver
import com.simvault.gateway.receiver.SmsSentReceiver
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID

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
        val activeList = runCatching { subManager.activeSubscriptionInfoList }.getOrNull() ?: return emptyList()
        return activeList
            .sortedBy { it.simSlotIndex }
            .map { info ->
                val rawNumber = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    runCatching { subManager.getPhoneNumber(info.subscriptionId) }.getOrDefault("")
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

    fun hasSimHardwareReady(): Boolean {
        if (listActiveSims().isNotEmpty()) return true
        val telephony = context.getSystemService(TelephonyManager::class.java)
        if (telephony != null) {
            val state = telephony.simState
            if (state != TelephonyManager.SIM_STATE_ABSENT && state != TelephonyManager.SIM_STATE_UNKNOWN) {
                return true
            }
        }
        val defaultSmsSubId = SubscriptionManager.getDefaultSmsSubscriptionId()
        return defaultSmsSubId != SubscriptionManager.INVALID_SUBSCRIPTION_ID
    }

    private fun resolveSmsManagerForSubId(subscriptionId: Int): SmsManager? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(SmsManager::class.java)
                ?.createForSubscriptionId(subscriptionId)
        } else {
            @Suppress("DEPRECATION")
            SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        }
    }

    private fun resolveDefaultSmsManager(): SmsManager? {
        val defaultSmsSubId = SubscriptionManager.getDefaultSmsSubscriptionId()
        if (defaultSmsSubId != SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
            resolveSmsManagerForSubId(defaultSmsSubId)?.let { return it }
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(SmsManager::class.java)
        } else {
            @Suppress("DEPRECATION")
            SmsManager.getDefault()
        }
    }

    private suspend fun dispatchViaSmsManager(
        smsManager: SmsManager,
        jobId: String,
        toE164: String,
        body: String,
        parts: ArrayList<String>,
        includeDeliveryReceipt: Boolean
    ): SmsDispatchOutcome {
        val nonce = UUID.randomUUID().toString()
        val resultDeferred = CompletableDeferred<SmsDispatchOutcome>()
        SmsSentReceiver.registerTracker(nonce, parts.size, resultDeferred)

        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return try {
            val sentIntents = ArrayList<PendingIntent>(parts.size)
            val deliveryIntents = if (includeDeliveryReceipt) ArrayList<PendingIntent>(parts.size) else null

            for (index in parts.indices) {
                val sentIntent = Intent(context, SmsSentReceiver::class.java).apply {
                    setPackage(context.packageName)
                    action = SmsSentReceiver.ACTION_SMS_SENT
                    putExtra(SmsSentReceiver.EXTRA_NONCE, nonce)
                    putExtra(SmsSentReceiver.EXTRA_PART_INDEX, index)
                }
                sentIntents.add(
                    PendingIntent.getBroadcast(
                        context,
                        (jobId + "_" + nonce + "_sent_$index").hashCode(),
                        sentIntent,
                        flags
                    )
                )

                if (deliveryIntents != null) {
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
            }

            if (parts.size > 1) {
                smsManager.sendMultipartTextMessage(toE164, null, parts, sentIntents, deliveryIntents)
            } else {
                smsManager.sendTextMessage(toE164, null, body, sentIntents[0], deliveryIntents?.get(0))
            }

            withTimeoutOrNull(20_000L) { resultDeferred.await() } ?: SmsDispatchOutcome.DeliveryUnknown
        } catch (_: SecurityException) {
            SmsDispatchOutcome.Failed("PERMISSION_REVOKED")
        } catch (e: Exception) {
            val errTag = e.javaClass.simpleName.uppercase().replace(Regex("[^A-Z0-9_]"), "").take(24)
            SmsDispatchOutcome.Failed("SMS_SEND_EX_${errTag.ifBlank { "ERROR" }}")
        } finally {
            SmsSentReceiver.unregisterTracker(nonce)
        }
    }

    suspend fun sendSms(
        jobId: String,
        toE164: String,
        body: String,
        simSlot: Int,
        mockMode: Boolean,
        requestDeliveryReceipts: Boolean = true
    ): SmsDispatchOutcome {
        val cleanTo = toE164.trim()
        if (!e164Regex.matches(cleanTo)) {
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
        val targetSim = activeSims.firstOrNull { it.slotIndex == simSlot } ?: activeSims.firstOrNull()

        val smsManager = if (targetSim != null) {
            resolveSmsManagerForSubId(targetSim.subscriptionId)
        } else if (hasSimHardwareReady()) {
            resolveDefaultSmsManager()
        } else {
            return SmsDispatchOutcome.Failed("SIM_CARD_ABSENT")
        } ?: return SmsDispatchOutcome.Failed("SMS_MANAGER_UNAVAILABLE")

        val parts = smsManager.divideMessage(body)
        if (parts.isEmpty()) {
            return SmsDispatchOutcome.Failed("EMPTY_SMS_BODY")
        }

        val firstAttempt = dispatchViaSmsManager(
            smsManager = smsManager,
            jobId = jobId,
            toE164 = cleanTo,
            body = body,
            parts = parts,
            includeDeliveryReceipt = requestDeliveryReceipts
        )

        // Many IMS/VoLTE carriers reject TP-SRR delivery receipts (RESULT_ERROR_GENERIC_FAILURE).
        // Because SMSC rejected submission before radio transmission, retrying once without deliveryIntent is safe.
        if (requestDeliveryReceipts &&
            firstAttempt is SmsDispatchOutcome.Failed &&
            (firstAttempt.errorCode == "SMS_GENERIC_FAILURE" || firstAttempt.errorCode == "SMS_NULL_PDU")
        ) {
            return dispatchViaSmsManager(
                smsManager = smsManager,
                jobId = jobId,
                toE164 = cleanTo,
                body = body,
                parts = parts,
                includeDeliveryReceipt = false
            )
        }

        return firstAttempt
    }
}
