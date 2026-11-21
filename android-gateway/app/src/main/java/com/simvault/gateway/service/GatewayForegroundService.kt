package com.simvault.gateway.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.simvault.gateway.MainActivity
import com.simvault.gateway.R
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.worker.GatewayPollEngine
import com.simvault.gateway.worker.PollCycleOutcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class GatewayForegroundService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollLoopJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        val store = SecureCredentialStore(this)
        if (!store.isEnrolled() || !store.isBackgroundServiceEnabled()) {
            stopSelf()
            return START_NOT_STICKY
        }

        val initialNote = buildNotification("Starting live 2.5s OTP poll...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, initialNote, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, initialNote)
        }

        startPollLoop()
        return START_STICKY
    }

    private fun startPollLoop() {
        if (pollLoopJob?.isActive == true) return

        pollLoopJob = serviceScope.launch {
            var backoffMs = BASE_POLL_INTERVAL_MS
            val store = SecureCredentialStore(applicationContext)

            while (isActive) {
                if (!store.isEnrolled() || !store.isBackgroundServiceEnabled()) {
                    stopSelf()
                    break
                }

                when (val outcome = GatewayPollEngine.runPollCycle(applicationContext)) {
                    is PollCycleOutcome.Success -> {
                        backoffMs = when {
                            store.isPaused() || outcome.serverStatus == "paused" -> 15_000L
                            outcome.hasMoreLikely -> BATCH_CONTINUE_DELAY_MS
                            else -> BASE_POLL_INTERVAL_MS
                        }
                        val modeLabel = if (store.isPaused()) "Paused locally"
                        else if (store.isMockMode()) "Mock mode · 2.5s poll"
                        else "Online · 2.5s OTP poll"
                        updateNotification("$modeLabel · Sent: ${store.getTotalDispatchedCount()}")
                    }
                    is PollCycleOutcome.AuthRevoked -> {
                        updateNotification("Device revoked on server. Open app to re-pair.")
                        stopSelf()
                        break
                    }
                    is PollCycleOutcome.NotEnrolled -> {
                        stopSelf()
                        break
                    }
                    is PollCycleOutcome.TransientError -> {
                        updateNotification("Reconnecting (${outcome.reason.take(40)})")
                        backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
                    }
                }

                delay(backoffMs)
            }
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java) ?: return
            val existing = mgr.getNotificationChannel(CHANNEL_ID)
            if (existing == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "SimVault Live Gateway",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Keeps the SimVault SMS & OTP gateway connected in the background."
                    setShowBadge(false)
                }
                mgr.createNotificationChannel(channel)
            }
        }
    }

    private fun buildNotification(contentText: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPending = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("SimVault Gateway")
            .setContentText(contentText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(contentPending)
            .build()
    }

    private fun updateNotification(contentText: String) {
        val mgr = getSystemService(NotificationManager::class.java) ?: return
        mgr.notify(NOTIFICATION_ID, buildNotification(contentText))
    }

    override fun onDestroy() {
        pollLoopJob?.cancel()
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL_ID = "simvault_gateway_channel"
        private const val NOTIFICATION_ID = 4109
        private const val BASE_POLL_INTERVAL_MS = 2_500L
        private const val BATCH_CONTINUE_DELAY_MS = 150L
        private const val MAX_BACKOFF_MS = 30_000L
        private const val ACTION_STOP = "com.simvault.gateway.action.STOP_SERVICE"

        fun start(context: Context) {
            val appCtx = context.applicationContext
            val store = SecureCredentialStore(appCtx)
            if (!store.isEnrolled() || !store.isBackgroundServiceEnabled()) return
            val intent = Intent(appCtx, GatewayForegroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appCtx.startForegroundService(intent)
            } else {
                appCtx.startService(intent)
            }
        }

        fun stop(context: Context) {
            val appCtx = context.applicationContext
            appCtx.stopService(Intent(appCtx, GatewayForegroundService::class.java))
        }
    }
}
