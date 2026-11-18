package com.simvault.gateway.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.simvault.gateway.data.GatewayApiException
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.network.SimVaultGatewayClient

class DeliveryReportWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val jobId = inputData.getString(KEY_JOB_ID) ?: return Result.failure()
        val store = SecureCredentialStore(applicationContext)
        if (!store.isEnrolled()) return Result.success()

        return try {
            SimVaultGatewayClient().reportDeliveryReceipt(
                serverUrl = store.getServerUrl(),
                deviceToken = store.getDeviceToken(),
                jobId = jobId
            )
            Result.success()
        } catch (e: GatewayApiException) {
            if (e.isAuthRevoked || e.httpCode in 400..499) Result.failure() else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        private const val KEY_JOB_ID = "job_id"

        fun enqueue(context: Context, jobId: String) {
            val req = OneTimeWorkRequestBuilder<DeliveryReportWorker>()
                .setInputData(Data.Builder().putString(KEY_JOB_ID, jobId).build())
                .build()
            WorkManager.getInstance(context).enqueue(req)
        }
    }
}
