package com.simvault.gateway.worker

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.simvault.gateway.BuildConfig
import com.simvault.gateway.data.GatewayApiException
import com.simvault.gateway.data.JournalEntry
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.LocalJobState
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.network.SimVaultGatewayClient
import com.simvault.gateway.sms.NativeSmsSender
import com.simvault.gateway.sms.SmsDispatchOutcome
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit

class GatewayPollWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    private fun isJobExpired(expiresAtIso: String): Boolean {
        return try {
            Instant.now().isAfter(Instant.parse(expiresAtIso))
        } catch (_: Exception) {
            false
        }
    }

    override suspend fun doWork(): Result {
        val store = SecureCredentialStore(applicationContext)
        if (!store.isEnrolled()) return Result.success()

        val client = SimVaultGatewayClient()
        val smsSender = NativeSmsSender(applicationContext)
        val journal = LocalJobJournal(applicationContext)

        val serverUrl = store.getServerUrl()
        val token = store.getDeviceToken()
        val hasPerm = smsSender.hasSendSmsPermission()
        val sims = smsSender.listActiveSims()
        val chosenSlot = store.getSelectedSimSlot()
        val activeSim = sims.firstOrNull { it.slotIndex == chosenSlot } ?: sims.firstOrNull()
        val simReady = store.isMockMode() || (hasPerm && activeSim != null)

        return try {
            val heartbeat = client.sendHeartbeat(
                serverUrl = serverUrl,
                deviceToken = token,
                appVersion = BuildConfig.VERSION_NAME,
                androidVersion = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                permissionSendSms = hasPerm,
                networkType = readNetworkType(),
                batteryPct = readBatteryPct(),
                simReady = simReady,
                simSlot = activeSim?.slotIndex ?: chosenSlot,
                carrierLabel = activeSim?.carrierLabel,
                maskedMsisdn = activeSim?.maskedMsisdn
            )
            store.setLastHeartbeat(heartbeat.serverTime)
            store.setServerStatus(heartbeat.status)
            store.setLastError(null)

            if (store.isPaused() || heartbeat.status == "paused") {
                return Result.success()
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
                    }
                    is SmsDispatchOutcome.DeliveryUnknown -> {
                        client.reportResult(serverUrl, token, job.jobId, "delivery_unknown", "AMBIGUOUS_SEND_STATE")
                        journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.DELIVERY_UNKNOWN, "AMBIGUOUS_SEND_STATE"))
                    }
                    is SmsDispatchOutcome.Failed -> {
                        client.reportResult(serverUrl, token, job.jobId, "failed", outcome.errorCode)
                        journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, outcome.errorCode))
                    }
                }
            }

            Result.success()
        } catch (e: GatewayApiException) {
            store.setLastError(e.message ?: e.errorCode)
            if (e.isAuthRevoked) {
                store.setServerStatus("revoked")
                Result.failure()
            } else {
                Result.retry()
            }
        } catch (e: Exception) {
            store.setLastError(e.message ?: "Network error during poll")
            Result.retry()
        }
    }

    private fun readBatteryPct(): Int {
        val intent = applicationContext.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = intent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) (level * 100) / scale else 100
    }

    private fun readNetworkType(): String {
        val cm = applicationContext.getSystemService(ConnectivityManager::class.java) ?: return "Unknown"
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "Offline"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            else -> "Connected"
        }
    }

    companion object {
        private const val PERIODIC_WORK_NAME = "simvault_gateway_periodic_poll"

        fun schedulePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val req = PeriodicWorkRequestBuilder<GatewayPollWorker>(15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                req
            )
        }

        fun triggerImmediatePoll(context: Context): UUID {
            val req = OneTimeWorkRequestBuilder<GatewayPollWorker>().build()
            WorkManager.getInstance(context).enqueue(req)
            return req.id
        }
    }
}
