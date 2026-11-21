package com.simvault.gateway.network

import com.simvault.gateway.data.EnrollmentResult
import com.simvault.gateway.data.GatewayApiException
import com.simvault.gateway.data.GatewayPollResult
import com.simvault.gateway.data.HealthCheckResult
import com.simvault.gateway.data.HeartbeatResult
import com.simvault.gateway.data.LeasedJob
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.TimeUnit

class SimVaultGatewayClient {

    private val client: OkHttpClient
        get() = sharedHttpClient

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private fun <T> executeWithSocketRecovery(block: () -> T): T {
        var attempt = 0
        while (true) {
            try {
                return block()
            } catch (e: IOException) {
                resetConnections()
                if (attempt >= 1) {
                    throw e
                }
                attempt++
                try {
                    Thread.sleep(250)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw e
                }
            }
        }
    }

    private fun requireHttps(serverUrl: String): String {
        val normalized = serverUrl.trim().trimEnd('/')
        val uri = runCatching { java.net.URI(normalized) }.getOrNull()
        if (uri == null || !uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank() || !uri.userInfo.isNullOrEmpty()) {
            throw IllegalArgumentException("Valid HTTPS server URL (without embedded credentials) is required.")
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

    fun checkHealth(serverUrl: String): HealthCheckResult = executeWithSocketRecovery {
        val baseUrl = requireHttps(serverUrl)
        val req = Request.Builder()
            .url("$baseUrl/health")
            .get()
            .build()

        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Health check failed")
            }
            val json = JSONObject(raw)
            HealthCheckResult(
                status = json.optString("status", "unknown"),
                version = json.optString("version", "1.0.0"),
                mode = json.optString("mode", "production"),
                database = json.optString("database", "unknown"),
                queueDepth = json.optInt("queue_depth", 0)
            )
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
    ): HeartbeatResult = executeWithSocketRecovery {
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
            HeartbeatResult(
                deviceId = json.optString("device_id"),
                status = json.optString("status", "online"),
                serverTime = json.getString("server_time")
            )
        }
    }

    private fun parseLeasedJob(json: JSONObject): LeasedJob {
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

    fun pollGateway(
        serverUrl: String,
        deviceToken: String,
        includeTelemetry: Boolean,
        appVersion: String,
        androidVersion: String,
        permissionSendSms: Boolean,
        networkType: String,
        batteryPct: Int,
        simReady: Boolean,
        simSlot: Int = 0,
        carrierLabel: String? = null,
        maskedMsisdn: String? = null,
        skipJobPoll: Boolean = false
    ): GatewayPollResult = executeWithSocketRecovery {
        val baseUrl = requireHttps(serverUrl)
        val body = JSONObject().apply {
            if (skipJobPoll) put("skip_job_poll", true)
            if (includeTelemetry) {
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
        }
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/poll")
            .header("Authorization", "Bearer $deviceToken")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()

        client.newCall(req).execute().use { res ->
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Poll failed")
            }
            val json = JSONObject(raw)
            val jobJson = json.optJSONObject("job")
            GatewayPollResult(
                deviceId = json.optString("device_id"),
                status = json.optString("status", "online"),
                serverTime = json.getString("server_time"),
                job = jobJson?.let { parseLeasedJob(it) }
            )
        }
    }

    fun pollNextJob(serverUrl: String, deviceToken: String): LeasedJob? = executeWithSocketRecovery {
        val baseUrl = requireHttps(serverUrl)
        val req = Request.Builder()
            .url("$baseUrl/v1/gateway/jobs/next")
            .header("Authorization", "Bearer $deviceToken")
            .get()
            .build()

        client.newCall(req).execute().use { res ->
            if (res.code == 204) return@executeWithSocketRecovery null
            val raw = res.body?.string().orEmpty()
            if (!res.isSuccessful) {
                throw parseApiError(res.code, raw, "Poll failed")
            }
            parseLeasedJob(JSONObject(raw))
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
    ) = executeWithSocketRecovery {
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

    fun reportDeliveryReceipt(serverUrl: String, deviceToken: String, jobId: String) = executeWithSocketRecovery {
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

    companion object {
        // Prefer IPv4 first on dual-stack cellular (avoids 5G->4G IPv6 prefix-change blackhole timeouts)
        private val resilientDns = Dns { hostname ->
            val addresses = Dns.SYSTEM.lookup(hostname)
            val v4 = addresses.filterIsInstance<Inet4Address>()
            val v6 = addresses.filterIsInstance<Inet6Address>()
            if (v4.isNotEmpty()) v4 + v6 else addresses
        }

        private val sharedHttpClient: OkHttpClient = OkHttpClient.Builder()
            .dns(resilientDns)
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .writeTimeout(6, TimeUnit.SECONDS)
            .callTimeout(14, TimeUnit.SECONDS)
            .pingInterval(15, TimeUnit.SECONDS)
            .connectionPool(ConnectionPool(2, 45, TimeUnit.SECONDS))
            .retryOnConnectionFailure(true)
            .build()

        fun resetConnections() {
            sharedHttpClient.connectionPool.evictAll()
        }
    }
}
