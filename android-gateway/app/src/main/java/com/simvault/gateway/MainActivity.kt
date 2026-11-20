package com.simvault.gateway

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.simvault.gateway.data.AppThemeMode
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.LocalJobState
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.network.SimVaultGatewayClient
import com.simvault.gateway.service.GatewayForegroundService
import com.simvault.gateway.sms.NativeSmsSender
import com.simvault.gateway.worker.GatewayPollEngine
import com.simvault.gateway.worker.GatewayPollWorker
import com.simvault.gateway.worker.PollCycleOutcome
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val Slate950 = Color(0xFF090D16)
private val Slate900 = Color(0xFF0F172A)
private val Slate800 = Color(0xFF1E293B)
private val Slate700 = Color(0xFF334155)
private val Slate400 = Color(0xFF94A3B8)
private val Slate500 = Color(0xFF64748B)
private val Slate100 = Color(0xFFF1F5F9)
private val Slate50 = Color(0xFFF8FAFC)

private val EmeraldLightBg = Color(0xFFD1FAE5)
private val EmeraldLightFg = Color(0xFF047857)
private val EmeraldDarkBg = Color(0xFF064E3B)
private val EmeraldDarkFg = Color(0xFF6EE7B7)

private val AmberLightBg = Color(0xFFFEF3C7)
private val AmberLightFg = Color(0xFFB45309)
private val AmberDarkBg = Color(0xFF451A03)
private val AmberDarkFg = Color(0xFFFCD34D)

private val RoseLightBg = Color(0xFFFFE4E6)
private val RoseLightFg = Color(0xFFBE123C)
private val RoseDarkBg = Color(0xFF4C0519)
private val RoseDarkFg = Color(0xFFFDA4AF)

private val BlueLightBg = Color(0xFFDBEAFE)
private val BlueLightFg = Color(0xFF1D4ED8)
private val BlueDarkBg = Color(0xFF172554)
private val BlueDarkFg = Color(0xFF93C5FD)

private val SimVaultLightColorScheme = lightColorScheme(
    primary = Slate900,
    onPrimary = Color.White,
    secondary = EmeraldLightFg,
    onSecondary = Color.White,
    background = Slate50,
    surface = Color.White,
    surfaceVariant = Slate100,
    onBackground = Slate900,
    onSurface = Slate900,
    onSurfaceVariant = Slate500,
    outline = Color(0xFFCBD5E1),
    error = RoseLightFg,
    onError = Color.White
)

private val SimVaultDarkColorScheme = darkColorScheme(
    primary = Color(0xFF3B82F6),
    onPrimary = Color.White,
    secondary = EmeraldDarkFg,
    onSecondary = Slate950,
    background = Slate950,
    surface = Slate900,
    surfaceVariant = Slate800,
    onBackground = Slate50,
    onSurface = Slate50,
    onSurfaceVariant = Slate400,
    outline = Slate700,
    error = RoseDarkFg,
    onError = Slate950
)

private val TimeFormatter: DateTimeFormatter =
    DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())

private fun formatEpoch(epochMs: Long): String {
    return runCatching { TimeFormatter.format(Instant.ofEpochMilli(epochMs)) }.getOrDefault("--:--:--")
}

private fun formatHeartbeatIso(iso: String): String {
    if (iso.isBlank() || iso == "Never") return "Never"
    return runCatching { TimeFormatter.format(Instant.parse(iso)) }.getOrDefault(iso)
}

private fun hasNotificationPermission(context: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    } else {
        true
    }
}

private fun isIgnoringBatteryOptimizations(context: Context): Boolean {
    val pm = context.getSystemService(PowerManager::class.java) ?: return false
    return pm.isIgnoringBatteryOptimizations(context.packageName)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.parseColor("#0F172A"))
        )
        setContent {
            val context = LocalContext.current
            val store = remember { SecureCredentialStore(context) }
            var themeMode by remember { mutableStateOf(store.getThemeMode()) }
            val systemDark = isSystemInDarkTheme()
            val isDark = when (themeMode) {
                AppThemeMode.SYSTEM -> systemDark
                AppThemeMode.LIGHT -> false
                AppThemeMode.DARK -> true
            }

            MaterialTheme(colorScheme = if (isDark) SimVaultDarkColorScheme else SimVaultLightColorScheme) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    GatewayConsoleScreen(
                        isDark = isDark,
                        themeMode = themeMode,
                        onThemeModeChange = { nextMode ->
                            themeMode = nextMode
                            store.setThemeMode(nextMode)
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(label: String, containerColor: Color, contentColor: Color) {
    Surface(
        color = containerColor,
        shape = RoundedCornerShape(6.dp)
    ) {
        Text(
            text = label,
            color = contentColor,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

@Composable
private fun MetricTile(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(8.dp),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@SuppressLint("BatteryLife")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GatewayConsoleScreen(
    isDark: Boolean,
    themeMode: AppThemeMode,
    onThemeModeChange: (AppThemeMode) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { SecureCredentialStore(context) }
    val sender = remember { NativeSmsSender(context) }
    val journal = remember { LocalJobJournal(context) }
    val client = remember { SimVaultGatewayClient() }

    val emeraldBg = if (isDark) EmeraldDarkBg else EmeraldLightBg
    val emeraldFg = if (isDark) EmeraldDarkFg else EmeraldLightFg
    val amberBg = if (isDark) AmberDarkBg else AmberLightBg
    val amberFg = if (isDark) AmberDarkFg else AmberLightFg
    val roseBg = if (isDark) RoseDarkBg else RoseLightBg
    val roseFg = if (isDark) RoseDarkFg else RoseLightFg
    val blueBg = if (isDark) BlueDarkBg else BlueLightBg
    val blueFg = if (isDark) BlueDarkFg else BlueLightFg

    var enrolled by remember { mutableStateOf(store.isEnrolled()) }
    var serverUrl by remember { mutableStateOf(store.getServerUrl().ifBlank { BuildConfig.DEFAULT_SERVER_URL }) }
    var enrollToken by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("${Build.MANUFACTURER} ${Build.MODEL}") }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var statusIsError by remember { mutableStateOf(false) }
    var isPairing by remember { mutableStateOf(false) }
    var isTestingHealth by remember { mutableStateOf(false) }
    var isPolling by remember { mutableStateOf(false) }
    var showUnpairDialog by remember { mutableStateOf(false) }

    var paused by remember { mutableStateOf(store.isPaused()) }
    var mockMode by remember { mutableStateOf(store.isMockMode()) }
    var autoPoll by remember { mutableStateOf(store.isAutoPollEnabled()) }
    var bgServiceEnabled by remember { mutableStateOf(store.isBackgroundServiceEnabled()) }
    var selectedSlot by remember { mutableIntStateOf(store.getSelectedSimSlot()) }
    var lastHeartbeat by remember { mutableStateOf(store.getLastHeartbeat()) }
    var serverStatus by remember { mutableStateOf(store.getServerStatus()) }
    var lastError by remember { mutableStateOf(store.getLastError()) }
    var totalDispatched by remember { mutableIntStateOf(store.getTotalDispatchedCount()) }
    var batteryPct by remember { mutableIntStateOf(GatewayPollEngine.readBatteryPct(context)) }
    var networkType by remember { mutableStateOf(GatewayPollEngine.readNetworkType(context)) }
    var batteryUnrestricted by remember { mutableStateOf(isIgnoringBatteryOptimizations(context)) }

    var hasSmsPerm by remember { mutableStateOf(sender.hasSendSmsPermission()) }
    var hasPhonePerm by remember { mutableStateOf(sender.hasReadPhoneStatePermission()) }
    var hasNotifPerm by remember { mutableStateOf(hasNotificationPermission(context)) }
    var sims by remember { mutableStateOf(sender.listActiveSims()) }
    var recentJobs by remember { mutableStateOf(journal.readAll()) }

    fun refreshLocalState() {
        lastHeartbeat = store.getLastHeartbeat()
        serverStatus = store.getServerStatus()
        lastError = store.getLastError()
        totalDispatched = store.getTotalDispatchedCount()
        batteryPct = GatewayPollEngine.readBatteryPct(context)
        networkType = GatewayPollEngine.readNetworkType(context)
        batteryUnrestricted = isIgnoringBatteryOptimizations(context)
        hasSmsPerm = sender.hasSendSmsPermission()
        hasPhonePerm = sender.hasReadPhoneStatePermission()
        hasNotifPerm = hasNotificationPermission(context)
        sims = sender.listActiveSims()
        recentJobs = journal.readAll()
    }

    suspend fun runImmediatePoll(showFeedback: Boolean) {
        if (isPolling || !store.isEnrolled()) return
        isPolling = true
        try {
            val outcome = withContext(Dispatchers.IO) {
                GatewayPollEngine.runPollCycle(context)
            }
            refreshLocalState()
            if (showFeedback) {
                when (outcome) {
                    is PollCycleOutcome.Success -> {
                        statusIsError = false
                        statusMessage = if (outcome.dispatchedCount > 0) {
                            "Dispatched ${outcome.dispatchedCount} message(s)"
                        } else {
                            "Synced · Queue empty (${outcome.serverStatus})"
                        }
                    }
                    is PollCycleOutcome.AuthRevoked -> {
                        statusIsError = true
                        statusMessage = "Device token revoked on server. Unpair and re-enroll."
                    }
                    is PollCycleOutcome.TransientError -> {
                        statusIsError = true
                        statusMessage = "Poll error: ${outcome.reason}"
                    }
                    PollCycleOutcome.NotEnrolled -> Unit
                }
            }
        } finally {
            isPolling = false
        }
    }

    LaunchedEffect(enrolled, bgServiceEnabled) {
        if (enrolled && bgServiceEnabled) {
            GatewayForegroundService.start(context)
        } else {
            GatewayForegroundService.stop(context)
        }
    }

    LaunchedEffect(enrolled, autoPoll, bgServiceEnabled) {
        if (!enrolled) return@LaunchedEffect
        while (true) {
            if (bgServiceEnabled) {
                refreshLocalState()
                delay(3_000L)
            } else if (autoPoll) {
                runImmediatePoll(showFeedback = false)
                delay(8_000L)
            } else {
                refreshLocalState()
                delay(5_000L)
            }
        }
    }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        refreshLocalState()
    }

    if (showUnpairDialog) {
        AlertDialog(
            onDismissRequest = { showUnpairDialog = false },
            title = { Text("Unpair Gateway Device?") },
            text = {
                Text("This clears the stored Android Keystore device token on this phone and stops background polling. You will need a new enrollment token from the web console to reconnect.")
            },
            confirmButton = {
                Button(
                    colors = ButtonDefaults.buttonColors(containerColor = RoseLightFg),
                    onClick = {
                        GatewayForegroundService.stop(context)
                        store.clearCredentials()
                        enrolled = false
                        showUnpairDialog = false
                        refreshLocalState()
                        statusIsError = false
                        statusMessage = "Device unpaired cleanly."
                    }
                ) {
                    Text("Unpair", color = Color.White)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUnpairDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Slate900,
                    titleContentColor = Color.White
                ),
                title = {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(end = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("SimVault Gateway", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                            Text(
                                "v${BuildConfig.VERSION_NAME} · Android ${Build.VERSION.RELEASE}",
                                style = MaterialTheme.typography.labelSmall,
                                color = Slate400
                            )
                        }
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(
                                onClick = {
                                    val next = when (themeMode) {
                                        AppThemeMode.SYSTEM -> AppThemeMode.DARK
                                        AppThemeMode.DARK -> AppThemeMode.LIGHT
                                        AppThemeMode.LIGHT -> AppThemeMode.SYSTEM
                                    }
                                    onThemeModeChange(next)
                                },
                                colors = ButtonDefaults.textButtonColors(contentColor = Color.White)
                            ) {
                                Text(
                                    text = when (themeMode) {
                                        AppThemeMode.SYSTEM -> "Theme: Auto"
                                        AppThemeMode.DARK -> "Theme: Dark"
                                        AppThemeMode.LIGHT -> "Theme: Light"
                                    },
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }

                            if (enrolled) {
                                val (badgeBg, badgeFg, badgeText) = when {
                                    serverStatus == "revoked" -> Triple(roseBg, roseFg, "REVOKED")
                                    paused || serverStatus == "paused" -> Triple(amberBg, amberFg, "PAUSED")
                                    serverStatus == "online" -> Triple(emeraldBg, emeraldFg, "ONLINE")
                                    else -> Triple(Slate800, Color.White, serverStatus.uppercase())
                                }
                                StatusBadge(label = badgeText, containerColor = badgeBg, contentColor = badgeFg)
                            }
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            statusMessage?.let { msg ->
                item {
                    Surface(
                        color = if (statusIsError) roseBg else blueBg,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = msg,
                            color = if (statusIsError) roseFg else blueFg,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                        )
                    }
                }
            }

            if (!enrolled) {
                item {
                    ElevatedCard(
                        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text("Pair Android Gateway", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                            Text(
                                "Generate a one-time enrollment token in the SimVault Web Console under Gateway Devices, then pair this phone over HTTPS.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            OutlinedTextField(
                                value = serverUrl,
                                onValueChange = { serverUrl = it },
                                label = { Text("Server Base URL (HTTPS)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = enrollToken,
                                onValueChange = { enrollToken = it.uppercase() },
                                label = { Text("Enrollment Token") },
                                placeholder = { Text("ENROLL-XXXX-XXXX-XXXX") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = deviceName,
                                onValueChange = { deviceName = it },
                                label = { Text("Device Label") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                OutlinedButton(
                                    enabled = !isTestingHealth && !isPairing,
                                    onClick = {
                                        val normalizedUrl = serverUrl.trim().trimEnd('/')
                                        if (!normalizedUrl.startsWith("https://")) {
                                            statusIsError = true
                                            statusMessage = "Server URL must start with https://"
                                            return@OutlinedButton
                                        }
                                        isTestingHealth = true
                                        scope.launch {
                                            try {
                                                val h = withContext(Dispatchers.IO) { client.checkHealth(normalizedUrl) }
                                                statusIsError = false
                                                statusMessage = "Server reachable · DB: ${h.database} · Queue: ${h.queueDepth}"
                                            } catch (e: Exception) {
                                                statusIsError = true
                                                statusMessage = e.message ?: "Health check failed"
                                            } finally {
                                                isTestingHealth = false
                                            }
                                        }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(if (isTestingHealth) "Checking..." else "Test Server")
                                }

                                Button(
                                    enabled = !isPairing && !isTestingHealth,
                                    onClick = {
                                        val normalizedUrl = serverUrl.trim().trimEnd('/')
                                        if (!normalizedUrl.startsWith("https://")) {
                                            statusIsError = true
                                            statusMessage = "Server URL must start with https:// (cleartext HTTP is disabled)."
                                            return@Button
                                        }
                                        if (enrollToken.isBlank()) {
                                            statusIsError = true
                                            statusMessage = "Enter a one-time enrollment token."
                                            return@Button
                                        }
                                        isPairing = true
                                        scope.launch {
                                            try {
                                                val res = withContext(Dispatchers.IO) {
                                                    client.enroll(
                                                        normalizedUrl,
                                                        enrollToken,
                                                        deviceName.ifBlank { "Android Gateway" },
                                                        BuildConfig.VERSION_NAME,
                                                        "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
                                                    )
                                                }
                                                store.saveEnrollment(normalizedUrl, res.deviceId, res.deviceToken)
                                                enrolled = true
                                                enrollToken = ""
                                                GatewayPollWorker.schedulePeriodic(context)
                                                if (bgServiceEnabled) GatewayForegroundService.start(context)
                                                statusIsError = false
                                                statusMessage = "Paired as ${res.deviceId}"
                                                runImmediatePoll(showFeedback = false)
                                            } catch (e: Exception) {
                                                statusIsError = true
                                                statusMessage = e.message ?: "Pairing failed"
                                            } finally {
                                                isPairing = false
                                            }
                                        }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(if (isPairing) "Pairing..." else "Pair Device")
                                }
                            }
                        }
                    }
                }
            } else {
                item {
                    ElevatedCard(
                        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text("Gateway Control", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)

                            if (isPolling) {
                                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                MetricTile("Last Heartbeat", formatHeartbeatIso(lastHeartbeat), Modifier.weight(1f))
                                MetricTile("Dispatched", totalDispatched.toString(), Modifier.weight(0.75f))
                                MetricTile("Power / Net", "$batteryPct% · $networkType", Modifier.weight(1f))
                            }

                            Text(
                                "Device: ${store.getDeviceId()} · ${store.getServerUrl()}",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )

                            lastError?.let { err ->
                                Surface(
                                    color = roseBg,
                                    shape = RoundedCornerShape(6.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        "Last Error: $err",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = roseFg,
                                        modifier = Modifier.padding(8.dp)
                                    )
                                }
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                Button(
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = if (paused) EmeraldLightFg else MaterialTheme.colorScheme.primary
                                    ),
                                    onClick = {
                                        paused = !paused
                                        store.setPaused(paused)
                                        statusIsError = false
                                        statusMessage = if (paused) "Gateway paused locally" else "Gateway resumed"
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(if (paused) "Resume" else "Pause")
                                }
                                OutlinedButton(
                                    enabled = !isPolling,
                                    onClick = {
                                        scope.launch { runImmediatePoll(showFeedback = true) }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(if (isPolling) "Syncing..." else "Poll Now")
                                }
                                TextButton(onClick = { showUnpairDialog = true }) {
                                    Text("Unpair", color = roseFg)
                                }
                            }

                            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))

                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Background Live Service (5s OTP Poll)", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                                    Text(
                                        "Keeps polling when screen is off via persistent notification",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Switch(
                                    checked = bgServiceEnabled,
                                    onCheckedChange = { enabled ->
                                        bgServiceEnabled = enabled
                                        store.setBackgroundServiceEnabled(enabled)
                                        if (enabled) GatewayForegroundService.start(context)
                                        else GatewayForegroundService.stop(context)
                                    }
                                )
                            }

                            if (!bgServiceEnabled) {
                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text("Auto-Poll While Screen Open (8s)", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                                        Text(
                                            "WorkManager fallback runs every 15m in background",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Switch(
                                        checked = autoPoll,
                                        onCheckedChange = {
                                            autoPoll = it
                                            store.setAutoPollEnabled(it)
                                        }
                                    )
                                }
                            }

                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        if (mockMode) "Sandbox Mock Mode (SIM Bypassed)" else "Live SIM Dispatch Mode",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(
                                        if (mockMode) "Carrier SIM is NOT used while Mock Mode is ON"
                                        else "Jobs dispatch through selected physical SIM card",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (mockMode) amberFg else if (!hasSmsPerm) roseFg else emeraldFg
                                    )
                                }
                                Switch(
                                    checked = mockMode,
                                    onCheckedChange = {
                                        mockMode = it
                                        store.setMockMode(it)
                                    }
                                )
                            }
                        }
                    }
                }
            }

            item {
                OutlinedCard(
                    colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Permissions, Battery & SIM Slot", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            StatusBadge(
                                label = if (hasSmsPerm) "SEND_SMS OK" else "SEND_SMS MISSING",
                                containerColor = if (hasSmsPerm) emeraldBg else roseBg,
                                contentColor = if (hasSmsPerm) emeraldFg else roseFg
                            )
                            StatusBadge(
                                label = if (hasPhonePerm) "PHONE OK" else "PHONE MISSING",
                                containerColor = if (hasPhonePerm) emeraldBg else roseBg,
                                contentColor = if (hasPhonePerm) emeraldFg else roseFg
                            )
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                StatusBadge(
                                    label = if (hasNotifPerm) "NOTIF OK" else "NOTIF OFF",
                                    containerColor = if (hasNotifPerm) emeraldBg else amberBg,
                                    contentColor = if (hasNotifPerm) emeraldFg else amberFg
                                )
                            }
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Button(
                                onClick = {
                                    val perms = mutableListOf(
                                        Manifest.permission.SEND_SMS,
                                        Manifest.permission.READ_PHONE_STATE
                                    )
                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                        perms.add(Manifest.permission.POST_NOTIFICATIONS)
                                    }
                                    permLauncher.launch(perms.toTypedArray())
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Grant Permissions")
                            }

                            if (!batteryUnrestricted) {
                                OutlinedButton(
                                    onClick = {
                                        val intent = Intent(
                                            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                                            Uri.parse("package:${context.packageName}")
                                        )
                                        runCatching { context.startActivity(intent) }
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Unrestrict Battery")
                                }
                            } else {
                                Box(
                                    contentAlignment = Alignment.Center,
                                    modifier = Modifier
                                        .weight(1f)
                                        .background(emeraldBg, RoundedCornerShape(8.dp))
                                        .padding(vertical = 10.dp)
                                ) {
                                    Text(
                                        "Battery Unrestricted",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = emeraldFg,
                                        fontWeight = FontWeight.SemiBold
                                    )
                                }
                            }
                        }

                        if (sims.isEmpty()) {
                            Text(
                                "No active SIM detected (or READ_PHONE_STATE permission not granted).",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                            sims.forEach { sim ->
                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            "SIM Slot ${sim.slotIndex} · ${sim.carrierLabel}",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Text(
                                            sim.maskedMsisdn,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    RadioButton(
                                        selected = selectedSlot == sim.slotIndex,
                                        onClick = {
                                            selectedSlot = sim.slotIndex
                                            store.setSelectedSimSlot(sim.slotIndex)
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "Local Job Journal (${recentJobs.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    if (recentJobs.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                journal.clear()
                                recentJobs = emptyList()
                            }
                        ) {
                            Text("Clear")
                        }
                    }
                }
            }

            if (recentJobs.isEmpty()) {
                item {
                    Text(
                        "No SMS jobs processed on this device yet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                items(recentJobs, key = { it.jobId }) { entry ->
                    val (badgeBg, badgeFg) = when (entry.state) {
                        LocalJobState.DELIVERED, LocalJobState.SENT_TO_NETWORK -> emeraldBg to emeraldFg
                        LocalJobState.FAILED -> roseBg to roseFg
                        LocalJobState.DELIVERY_UNKNOWN -> amberBg to amberFg
                        LocalJobState.RECEIVED, LocalJobState.ACCEPTED -> blueBg to blueFg
                    }
                    OutlinedCard(
                        colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    entry.jobId,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                StatusBadge(entry.state.name, badgeBg, badgeFg)
                            }
                            Text(
                                "To ${entry.destinationMasked} · Slot ${entry.simSlot} · ${formatEpoch(entry.updatedAtEpochMs)}" +
                                    (entry.errorCode?.let { " · $it" } ?: ""),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
