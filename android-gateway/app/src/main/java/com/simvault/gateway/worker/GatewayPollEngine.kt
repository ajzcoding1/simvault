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
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
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
    private const val STALE_ACCEPTED_TIMEOUT_MS = 20_000L

    private val pollMutex = Mutex()
    private var lastTelemetrySentAtMs: Long = 0L
    private var lastTelemetryFingerprint: String = ""
    private var lastNetworkType: String? = null

    private fun isJobExpired(expiresAtIso: String): Boolean {
        return try {
            Instant.now().isAfter(Instant.parse(expiresAtIso))
        } catch (_: Exception) {
            false
        }
    }

    private fun hasInternetCapability(context: Context): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return true
        val active = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(active) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun reportResultSafely(
        client: SimVaultGatewayClient,
        serverUrl: String,
        token: String,
        jobId: String,
        status: String,
        errorCode: String? = null
    ) {
        try {
            client.reportResult(serverUrl, token, jobId, status, errorCode)
        } catch (e: GatewayApiException) {
            // 404/409 means lease expired or job was already finalized (e.g. delivery receipt arrived first)
            if (e.httpCode != 404 && e.httpCode != 409) {
                throw e
            }
        }
    }

    private fun reportDeliverySafely(
        client: SimVaultGatewayClient,
        serverUrl: String,
        token: String,
        jobId: String
    ) {
        try {
            client.reportDeliveryReceipt(serverUrl, token, jobId)
        } catch (e: GatewayApiException) {
            if (e.httpCode != 404 && e.httpCode != 409) {
                throw e
            }
        }
    }

    suspend fun runPollCycle(context: Context): PollCycleOutcome = pollMutex.withLock {
        val appContext = context.applicationContext
        val store = SecureCredentialStore(appContext)
        if (!store.isEnrolled()) return@withLock PollCycleOutcome.NotEnrolled

        val networkType = readNetworkType(appContext)
        if (lastNetworkType != null && lastNetworkType != networkType) {
            SimVaultGatewayClient.resetConnections()
        }
        lastNetworkType = networkType

        if (!hasInternetCapability(appContext)) {
            val msg = "Network switching (5G/4G) · waiting for data"
            store.setLastError(msg)
            return@withLock PollCycleOutcome.TransientError(msg)
        }

        val client = SimVaultGatewayClient()
        val smsSender = NativeSmsSender(appContext)
        val journal = LocalJobJournal(appContext)

        val serverUrl = store.getServerUrl()
        val token = store.getDeviceToken()
        val hasPerm = smsSender.hasSendSmsPermission()
        val sims = smsSender.listActiveSims()
        val chosenSlot = store.getSelectedSimSlot()
        val activeSim = sims.firstOrNull { it.slotIndex == chosenSlot } ?: sims.firstOrNull()
        val simReady = store.isMockMode() || (hasPerm && (activeSim != null || smsSender.hasSimHardwareReady()))
        val locallyPaused = store.isPaused()
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
            val requestReceipts = store.isDeliveryReceiptRequested()

            for (iteration in 0 until MAX_JOBS_PER_CYCLE) {
                if (store.isPaused()) break
                val job = currentJob ?: break

                val existing = journal.findByJobId(job.jobId)
                if (existing == null) {
                    val jobSlot = activeSim?.slotIndex ?: chosenSlot
                    val masked = LocalJobJournal.maskE164(job.to)
                    journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.ACCEPTED))

                    if (isJobExpired(job.expiresAt)) {
                        journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, "TTL_EXPIRED"))
                        reportResultSafely(client, serverUrl, token, job.jobId, "failed", "TTL_EXPIRED")
                    } else {
                        val outcome = smsSender.sendSms(
                            jobId = job.jobId,
                            toE164 = job.to,
                            body = job.body,
                            simSlot = jobSlot,
                            mockMode = store.isMockMode(),
                            requestDeliveryReceipts = requestReceipts
                        )

                        // Persist local terminal outcome BEFORE reporting to server so network interruptions never cause duplicate sends or ACCEPTED deadlocks
                        when (outcome) {
                            is SmsDispatchOutcome.SentToNetwork -> {
                                journal.upsert(JournalEntry(job.jobId, masked, jobSlot, LocalJobState.SENT_TO_NETWORK))
                                store.incrementTotalDispatched()
                                dispatchedNow++
                                reportResultSafely(client, serverUrl, token, job.jobId, "sent_to_network")
                            }
                            is SmsDispatchOutcome.DeliveryUnknown -> {
                                journal.upsert(
                                    JournalEntry(job.jobId, masked, jobSlot, LocalJobState.DELIVERY_UNKNOWN, "AMBIGUOUS_SEND_STATE")
                                )
                                reportResultSafely(
                                    client,
                                    serverUrl,
                                    token,
                                    job.jobId,
                                    "delivery_unknown",
                                    "AMBIGUOUS_SEND_STATE"
                                )
                            }
                            is SmsDispatchOutcome.Failed -> {
                                journal.upsert(
                                    JournalEntry(job.jobId, masked, jobSlot, LocalJobState.FAILED, outcome.errorCode)
                                )
                                reportResultSafely(client, serverUrl, token, job.jobId, "failed", outcome.errorCode)
                            }
                        }
                    }
                } else {
                    // Re-leased job after prior /result network interruption: re-sync cached outcome without re-sending SMS
                    when (existing.state) {
                        LocalJobState.DELIVERED -> {
                            reportDeliverySafely(client, serverUrl, token, job.jobId)
                        }
                        LocalJobState.SENT_TO_NETWORK -> {
                            reportResultSafely(client, serverUrl, token, job.jobId, "sent_to_network")
                        }
                        LocalJobState.DELIVERY_UNKNOWN -> {
                            reportResultSafely(
                                client,
                                serverUrl,
                                token,
                                job.jobId,
                                "delivery_unknown",
                                existing.errorCode ?: "AMBIGUOUS_SEND_STATE"
                            )
                        }
                        LocalJobState.FAILED -> {
                            reportResultSafely(
                                client,
                                serverUrl,
                                token,
                                job.jobId,
                                "failed",
                                existing.errorCode ?: "SEND_FAILED"
                            )
                        }
                        LocalJobState.ACCEPTED, LocalJobState.RECEIVED -> {
                            if (System.currentTimeMillis() - existing.updatedAtEpochMs > STALE_ACCEPTED_TIMEOUT_MS) {
                                journal.upsert(
                                    existing.copy(
                                        state = LocalJobState.DELIVERY_UNKNOWN,
                                        errorCode = "PROCESS_INTERRUPTED",
                                        updatedAtEpochMs = System.currentTimeMillis()
                                    )
                                )
                                reportResultSafely(
                                    client,
                                    serverUrl,
                                    token,
                                    job.jobId,
                                    "delivery_unknown",
                                    "PROCESS_INTERRUPTED"
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
            SimVaultGatewayClient.resetConnections()
            val msg = when (e) {
                is SocketTimeoutException,
                is ConnectException,
                is UnknownHostException -> "Network switching (5G/4G) · reconnecting"
                else -> e.message ?: "Network error during poll"
            }
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
