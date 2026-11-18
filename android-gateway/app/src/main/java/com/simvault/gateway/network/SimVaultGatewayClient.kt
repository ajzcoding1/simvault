package com.simvault.gateway.network

import com.simvault.gateway.data.EnrollmentResult
import com.simvault.gateway.data.GatewayApiException
import com.simvault.gateway.data.HeartbeatResult
import com.simvault.gateway.data.LeasedJob
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class SimVaultGatewayClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private fun requireHttps(serverUrl: String): String {
        val normalized = serverUrl.trim().trimEnd('/')
        if (!normalized.startsWith("https://")) {
            throw IllegalArgumentException("HTTPS server URL is required for live gateway security.")
        }
        return normalized
    }

    private fun parseApiError(httpCode: Int, rawBody: String, fallback: String): GatewayApiException {
        return try {
            val errObj = JSONObject(rawBody).optJSONObject("error")
            val code = errObj?.optString("code")?.takeIf { it.isNotBlank() } ?: "HTTP_$httpCode"
            val msg = errObj?.optString("message")?.takeIf { it.isNotBlank() } ?: fallback
            GatewayApiException(httpCode, code, msg)
        } catch (_: Exception) {
            GatewayApiException(httpCode, "HTTP_$httpCode", "$fallback ($httpCode)")
        }
    }

    fun enroll(
        serverUrl: String,
        enrollmentToken: String,
        deviceName: String,
        appVersion: String,
        androidVersion: String
    ): EnrollmentResult {
        val baseUrl = requireHttps(serverUrl)
        val body = JSONObject().apply {
            put("enrollment_token", enrollmentToken.trim())
            put("device_name", deviceName.trim())
            put("app_version", appVersion)
            put("android_version", androidVersion)
        }
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/enroll")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()

        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Enrollment failed")
            }
            val json = JSONObject(raw)
            return EnrollmentResult(
                deviceId = json.getString("device_id"),
                deviceToken = json.getString("device_token"),
                enrolledAt = json.getString("enrolled_at")
            )
        }
    }

    fun sendHeartbeat(
        serverUrl: String,
        deviceToken: String,
        appVersion: String,
        androidVersion: String,
        permissionSendSms: Boolean,
        networkType: String,
        batteryPct: Int,
        simReady: Boolean,
        simSlot: Int = 0,
        carrierLabel: String? = null,
        maskedMsisdn: String? = null
    ): HeartbeatResult {
        val baseUrl = requireHttps(serverUrl)
        val body = JSONObject().apply {
            put("app_version", appVersion)
            put("android_version", androidVersion)
            put("permission_send_sms", permissionSendSms)
            put("network_type", networkType)
            put("battery_pct", batteryPct.coerceIn(0, 100))
            put("sim_ready", simReady)
            put("sim_slot", simSlot)
            if (!carrierLabel.isNullOrBlank()) put("carrier_label", carrierLabel)
            if (!maskedMsisdn.isNullOrBlank()) put("masked_msisdn", maskedMsisdn)
        }
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/heartbeat")
            .header("Authorization", "Bearer $deviceToken")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()

        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Heartbeat failed")
            }
            val json = JSONObject(raw)
            return HeartbeatResult(
                deviceId = json.optString("device_id"),
                status = json.optString("status", "online"),
                serverTime = json.getString("server_time")
            )
        }
    }

    fun pollNextJob(serverUrl: String, deviceToken: String): LeasedJob? {
        val baseUrl = requireHttps(serverUrl)
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/jobs/next")
            .header("Authorization", "Bearer $deviceToken")
            .get()
            .build()

        client.newCall(req).execute().use { res ->
            if (res.code == 204) return null
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Poll failed")
            }
            val json = JSONObject(raw)
            return LeasedJob(
                jobId = json.getString("job_id"),
                leaseToken = json.getString("lease_token"),
                to = json.getString("to"),
                body = json.getString("body"),
                simSlot = json.optInt("sim_slot", 0),
                isTest = json.optBoolean("is_test", false),
                expiresAt = json.getString("expires_at")
            )
        }
    }

    fun ackAccepted(serverUrl: String, deviceToken: String, jobId: String) {
        val baseUrl = requireHttps(serverUrl)
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/jobs/$jobId/accepted")
            .header("Authorization", "Bearer $deviceToken")
            .post("{}".toRequestBody(jsonMedia))
            .build()
        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Accept acknowledgement failed")
            }
        }
    }

    fun reportResult(
        serverUrl: String,
        deviceToken: String,
        jobId: String,
        status: String,
        errorCode: String? = null
    ) {
        val baseUrl = requireHttps(serverUrl)
        val body = JSONObject().apply {
            put("status", status)
            if (errorCode != null) put("error_code", errorCode)
        }
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/jobs/$jobId/result")
            .header("Authorization", "Bearer $deviceToken")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()
        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Report result failed")
            }
        }
    }

    fun reportDeliveryReceipt(serverUrl: String, deviceToken: String, jobId: String) {
        val baseUrl = requireHttps(serverUrl)
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/jobs/$jobId/delivery-report")
            .header("Authorization", "Bearer $deviceToken")
            .post("{}".toRequestBody(jsonMedia))
            .build()
        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Delivery receipt upload failed")
            }
        }
    }
}
