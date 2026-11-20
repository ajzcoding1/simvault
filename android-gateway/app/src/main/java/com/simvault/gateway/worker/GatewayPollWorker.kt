package com.simvault.gateway.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.UUID
import java.util.concurrent.TimeUnit

class GatewayPollWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        return when (GatewayPollEngine.runPollCycle(applicationContext)) {
            is PollCycleOutcome.Success,
            PollCycleOutcome.NotEnrolled -> Result.success()
            is PollCycleOutcome.AuthRevoked -> Result.failure()
            is PollCycleOutcome.TransientError -> Result.retry()
        }
    }

    companion object {
        private const val PERIODIC_WORK_NAME = "simvault_gateway_periodic_poll"
        private const val IMMEDIATE_WORK_NAME = "simvault_gateway_immediate_poll"

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
            WorkManager.getInstance(context).enqueueUniqueWork(
                IMMEDIATE_WORK_NAME,
                ExistingWorkPolicy.KEEP,
                req
            )
            return req.id
        }
    }
}
