package com.simvault.gateway.worker

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import com.simvault.gateway.BuildConfig
import com.simvault.gateway.data.GatewayApiException
import com.simvault.gateway.data.JournalEntry
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.LocalJobState
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.network.SimVaultGatewayClient
import com.simvault.gateway.sms.NativeSmsSender
import com.simvault.gateway.sms.SmsDispatchOutcome
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Instant

sealed class PollCycleOutcome {
    data class Success(val dispatchedCount: Int, val serverStatus: String) : PollCycleOutcome()
    data object NotEnrolled : PollCycleOutcome()
    data class AuthRevoked(val reason: String) : PollCycleOutcome()
    data class TransientError(val reason: String) : PollCycleOutcome()
}

object GatewayPollEngine {

    private val pollMutex = Mutex()

    private fun isJobExpired(expiresAtIso: String): Boolean {
        return try {
            Instant.now().isAfter(Instant.parse(expiresAtIso))
        } catch (_: Exception) {
            false
        }
    }

    suspend fun runPollCycle(context: Context): PollCycleOutcome = pollMutex.withLock {
        val appContext = context.applicationContext
        val store = SecureCredentialStore(appContext)
        if (!store.isEnrolled()) return@withLock PollCycleOutcome.NotEnrolled

        val client = SimVaultGatewayClient()
        val smsSender = NativeSmsSender(appContext)
        val journal = LocalJobJournal(appContext)

        val serverUrl = store.getServerUrl()
        val token = store.getDeviceToken()
        val hasPerm = smsSender.hasSendSmsPermission()
        val sims = smsSender.listActiveSims()
        val chosenSlot = store.getSelectedSimSlot()
        val activeSim = sims.firstOrNull { it.slotIndex == chosenSlot } ?: sims.firstOrNull()
        val simReady = store.isMockMode() || (hasPerm && activeSim != null)

        var dispatchedNow = 0

        return@withLock try {
            val heartbeat = client.sendHeartbeat(
                serverUrl = serverUrl,
                deviceToken = token,
                appVersion = BuildConfig.VERSION_NAME,
                androidVersion = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                permissionSendSms = hasPerm,
                networkType = readNetworkType(appContext),
                batteryPct = readBatteryPct(appContext),
                simReady = simReady,
                simSlot = activeSim?.slotIndex ?: chosenSlot,
                carrierLabel = activeSim?.carrierLabel,
                maskedMsisdn = activeSim?.maskedMsisdn
            )
            store.setLastHeartbeat(heartbeat.serverTime)
            store.setServerStatus(heartbeat.status)
            store.setLastError(null)

            if (store.isPaused() || heartbeat.status == "paused") {
                return@withLock PollCycleOutcome.Success(0, if (store.isPaused()) "paused_local" else heartbeat.status)
            }

            // Drain up to 5 queued jobs per poll wake
            for (iteration in 0 until 5) {
                if (store.isPaused()) break
                val job = client.pollNextJob(serverUrl, token) ?: break

                // Local duplicate protection across process restarts
                if (journal.hasProcessedOrInFlight(job.jobId)) {
                    continue
                }

                val jobSlot = activeSim?.slotIndex ?: chosenSlot
                val masked = LocalJobJournal.maskE164(job.to)
                journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.RECEIVED))
                client.ackAccepted(serverUrl, token, job.jobId)
                journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.ACCEPTED))

                if (isJobExpired(job.expiresAt)) {
                    client.reportResult(serverUrl, token, job.jobId, "failed", "TTL_EXPIRED")
                    journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, "TTL_EXPIRED"))
                    continue
                }

                val outcome = smsSender.sendSms(
                    jobId = job.jobId,
                    toE164 = job.to,
                    body = job.body,
                    simSlot = jobSlot,
                    mockMode = store.isMockMode()
                )

                when (outcome) {
                    is SmsDispatchOutcome.SentToNetwork -> {
                        client.reportResult(serverUrl, token, job.jobId, "sent_to_network")
                        journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.SENT_TO_NETWORK))
                        store.incrementTotalDispatched()
                        dispatchedNow++
                    }
                    is SmsDispatchOutcome.DeliveryUnknown -> {
                        client.reportResult(serverUrl, token, job.jobId, "delivery_unknown", "AMBIGUOUS_SEND_STATE")
                        journal.upsert(
                            JournalEntry(job.jobId, masked, jobSlot, LocalJobState.DELIVERY_UNKNOWN, "AMBIGUOUS_SEND_STATE")
                        )
                    }
                    is SmsDispatchOutcome.Failed -> {
                        client.reportResult(serverUrl, token, job.jobId, "failed", outcome.errorCode)
                        journal.upsert(
                            JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, outcome.errorCode)
                        )
                    }
                }
            }

            PollCycleOutcome.Success(dispatchedNow, heartbeat.status)
        } catch (e: GatewayApiException) {
            val msg = e.message ?: e.errorCode
            store.setLastError(msg)
            if (e.isAuthRevoked) {
                store.setServerStatus("revoked")
                PollCycleOutcome.AuthRevoked(msg)
            } else {
                PollCycleOutcome.TransientError(msg)
            }
        } catch (e: Exception) {
            val msg = e.message ?: "Network error during poll"
            store.setLastError(msg)
            PollCycleOutcome.TransientError(msg)
        }
    }

    fun readBatteryPct(context: Context): Int {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = intent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) (level * 100) / scale else 100
    }

    fun readNetworkType(context: Context): String {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return "Unknown"
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "Offline"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Connected"
        }
    }
}
