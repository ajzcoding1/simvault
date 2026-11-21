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
    data class Success(
        val dispatchedCount: Int,
        val serverStatus: String,
        val hasMoreLikely: Boolean = false
    ) : PollCycleOutcome()
    data object NotEnrolled : PollCycleOutcome()
    data class AuthRevoked(val reason: String) : PollCycleOutcome()
    data class TransientError(val reason: String) : PollCycleOutcome()
}

object GatewayPollEngine {

    private const val TELEMETRY_SYNC_INTERVAL_MS = 20_000L
    private const val MAX_JOBS_PER_CYCLE = 5

    private val pollMutex = Mutex()
    private var lastTelemetrySentAtMs: Long = 0L
    private var lastTelemetryFingerprint: String = ""

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
        val locallyPaused = store.isPaused()
        val networkType = readNetworkType(appContext)
        val batteryPct = readBatteryPct(appContext)
        val simSlot = activeSim?.slotIndex ?: chosenSlot
        val fingerprint = "$hasPerm|$simReady|$simSlot|$networkType|${batteryPct / 5}|${activeSim?.carrierLabel.orEmpty()}"
        val nowMs = System.currentTimeMillis()
        val shouldIncludeTelemetry =
            lastTelemetrySentAtMs == 0L ||
                fingerprint != lastTelemetryFingerprint ||
                (nowMs - lastTelemetrySentAtMs) >= TELEMETRY_SYNC_INTERVAL_MS

        var dispatchedNow = 0
        var reachedBatchLimit = false

        return@withLock try {
            val pollResult = client.pollGateway(
                serverUrl = serverUrl,
                deviceToken = token,
                includeTelemetry = shouldIncludeTelemetry,
                appVersion = BuildConfig.VERSION_NAME,
                androidVersion = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                permissionSendSms = hasPerm,
                networkType = networkType,
                batteryPct = batteryPct,
                simReady = simReady,
                simSlot = simSlot,
                carrierLabel = activeSim?.carrierLabel,
                maskedMsisdn = activeSim?.maskedMsisdn,
                skipJobPoll = locallyPaused
            )
            if (shouldIncludeTelemetry) {
                lastTelemetrySentAtMs = nowMs
                lastTelemetryFingerprint = fingerprint
            }
            store.setLastHeartbeat(pollResult.serverTime)
            store.setServerStatus(pollResult.status)
            store.setLastError(null)

            if (locallyPaused || pollResult.status == "paused") {
                return@withLock PollCycleOutcome.Success(0, if (locallyPaused) "paused_local" else pollResult.status)
            }

            // Process job returned in combined poll, then drain up to MAX_JOBS_PER_CYCLE queued jobs without extra idle calls
            var currentJob = pollResult.job
            for (iteration in 0 until MAX_JOBS_PER_CYCLE) {
                if (store.isPaused()) break
                val job = currentJob ?: break

                // Local duplicate protection across process restarts
                if (!journal.hasProcessedOrInFlight(job.jobId)) {
                    val jobSlot = activeSim?.slotIndex ?: chosenSlot
                    val masked = LocalJobJournal.maskE164(job.to)
                    journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.ACCEPTED))

                    if (isJobExpired(job.expiresAt)) {
                        client.reportResult(serverUrl, token, job.jobId, "failed", "TTL_EXPIRED")
                        journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, "TTL_EXPIRED"))
                    } else {
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
                }

                if (iteration == MAX_JOBS_PER_CYCLE - 1) {
                    reachedBatchLimit = true
                    break
                }
                currentJob = client.pollNextJob(serverUrl, token)
            }

            PollCycleOutcome.Success(dispatchedNow, pollResult.status, hasMoreLikely = reachedBatchLimit)
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
