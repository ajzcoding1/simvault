package com.simvault.gateway

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.work.WorkInfo
import androidx.work.WorkManager
import com.simvault.gateway.data.LocalJobJournal
import com.simvault.gateway.data.SecureCredentialStore
import com.simvault.gateway.network.SimVaultGatewayClient
import com.simvault.gateway.sms.NativeSmsSender
import com.simvault.gateway.worker.GatewayPollWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    GatewayConsoleScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GatewayConsoleScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val store = remember { SecureCredentialStore(context) }
    val sender = remember { NativeSmsSender(context) }
    val journal = remember { LocalJobJournal(context) }
    val client = remember { SimVaultGatewayClient() }
    val workManager = remember { WorkManager.getInstance(context) }

    var enrolled by remember { mutableStateOf(store.isEnrolled()) }
    var serverUrl by remember { mutableStateOf(store.getServerUrl().ifBlank { BuildConfig.DEFAULT_SERVER_URL }) }
    var enrollToken by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("${Build.MANUFACTURER} ${Build.MODEL}") }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isPairing by remember { mutableStateOf(false) }
    var isPolling by remember { mutableStateOf(false) }
    var showUnpairDialog by remember { mutableStateOf(false) }

    var paused by remember { mutableStateOf(store.isPaused()) }
    var mockMode by remember { mutableStateOf(store.isMockMode()) }
    var autoPoll by remember { mutableStateOf(store.isAutoPollEnabled()) }
    var selectedSlot by remember { mutableStateOf(store.getSelectedSimSlot()) }
    var lastHeartbeat by remember { mutableStateOf(store.getLastHeartbeat()) }
    var serverStatus by remember { mutableStateOf(store.getServerStatus()) }
    var lastError by remember { mutableStateOf(store.getLastError()) }
    var hasSmsPerm by remember { mutableStateOf(sender.hasSendSmsPermission()) }
    var hasPhonePerm by remember { mutableStateOf(sender.hasReadPhoneStatePermission()) }
    var sims by remember { mutableStateOf(sender.listActiveSims()) }
    var recentJobs by remember { mutableStateOf(journal.readAll()) }

    fun refreshLocalState() {
        lastHeartbeat = store.getLastHeartbeat()
        serverStatus = store.getServerStatus()
        lastError = store.getLastError()
        sims = sender.listActiveSims()
        recentJobs = journal.readAll()
    }

    suspend fun runImmediatePollAndWait() {
        if (isPolling || !store.isEnrolled()) return
        isPolling = true
        try {
            val workId = GatewayPollWorker.triggerImmediatePoll(context)
            workManager.getWorkInfoByIdFlow(workId).first { info ->
                info != null && info.state.isFinished
            }
            refreshLocalState()
            statusMessage = if (store.getServerStatus() == "revoked") {
                "Device token revoked on server. Unpair and re-enroll."
            } else if (store.getLastError() != null) {
                "Poll error: ${store.getLastError()}"
            } else {
                "Poll complete (${store.getServerStatus()})"
            }
        } finally {
            isPolling = false
        }
    }

    // Foreground live polling while screen is open
    LaunchedEffect(enrolled, paused, autoPoll) {
        if (!enrolled || !autoPoll) return@LaunchedEffect
        while (true) {
            runImmediatePollAndWait()
            delay(10_000L)
        }
    }

    val permLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        hasSmsPerm = sender.hasSendSmsPermission()
        hasPhonePerm = sender.hasReadPhoneStatePermission()
        sims = sender.listActiveSims()
    }

    if (showUnpairDialog) {
        AlertDialog(
            onDismissRequest = { showUnpairDialog = false },
            title = { Text("Unpair Gateway Device?") },
            text = {
                Text("This clears the stored Keystore device token on this phone. You will need a new one-time enrollment token from the web dashboard to reconnect.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        store.clearCredentials()
                        enrolled = false
                        showUnpairDialog = false
                        refreshLocalState()
                        statusMessage = "Device unpaired"
                    }
                ) {
                    Text("Unpair")
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
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("SimVault Gateway", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "v${BuildConfig.VERSION_NAME} · Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
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
            contentPadding = PaddingValues(vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (!enrolled) {
                item {
                    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Pair Device", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "Generate a one-time enrollment token in the SimVault Web Dashboard under Gateway Devices.",
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
                                onValueChange = { enrollToken = it },
                                label = { Text("One-Time Enrollment Token") },
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
                            Button(
                                enabled = !isPairing,
                                onClick = {
                                    val normalizedUrl = serverUrl.trim().trimEnd('/')
                                    if (!normalizedUrl.startsWith("https://")) {
                                        statusMessage = "Server URL must start with https:// (cleartext HTTP is disabled)."
                                        return@Button
                                    }
                                    if (enrollToken.isBlank()) {
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
                                            refreshLocalState()
                                            statusMessage = "Paired as ${res.deviceId}"
                                            runImmediatePollAndWait()
                                        } catch (e: Exception) {
                                            statusMessage = e.message ?: "Pairing failed"
                                        } finally {
                                            isPairing = false
                                        }
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(if (isPairing) "Pairing..." else "Pair Device")
                            }
                        }
                    }
                }
            } else {
                item {
                    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Gateway Status", style = MaterialTheme.typography.titleMedium)
                                Text(
                                    text = serverStatus.uppercase(),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = when (serverStatus) {
                                        "online" -> MaterialTheme.colorScheme.primary
                                        "revoked" -> MaterialTheme.colorScheme.error
                                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                                    }
                                )
                            }
                            Text("Device ID: ${store.getDeviceId()}", style = MaterialTheme.typography.bodySmall)
                            Text("Server: ${store.getServerUrl()}", style = MaterialTheme.typography.bodySmall)
                            Text("Last Heartbeat: $lastHeartbeat", style = MaterialTheme.typography.bodySmall)
                            lastError?.let { err ->
                                Text(
                                    "Last Error: $err",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        paused = !paused
                                        store.setPaused(paused)
                                        statusMessage = if (paused) "Gateway paused locally" else "Gateway resumed"
                                    }
                                ) {
                                    Text(if (paused) "Resume" else "Pause")
                                }
                                OutlinedButton(
                                    enabled = !isPolling,
                                    onClick = {
                                        scope.launch { runImmediatePollAndWait() }
                                    }
                                ) {
                                    Text(if (isPolling) "Polling..." else "Poll Now")
                                }
                                TextButton(onClick = { showUnpairDialog = true }) {
                                    Text("Unpair", color = MaterialTheme.colorScheme.error)
                                }
                            }

                            HorizontalDivider()

                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Auto-Poll While Open (10s)", style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        "WorkManager also polls in background every 15m",
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

                            Row(
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        if (mockMode) "Sandbox Mock Mode (SIM Bypassed)" else "Live SIM Mode Active",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Text(
                                        if (mockMode) {
                                            "Turn off to dispatch SMS through carrier SIM"
                                        } else {
                                            "Outbound jobs dispatch directly via selected carrier SIM"
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (!mockMode && !hasSmsPerm) {
                                            MaterialTheme.colorScheme.error
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        }
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
                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Permissions & SIM Status", style = MaterialTheme.typography.titleMedium)
                        Text("SEND_SMS: ${if (hasSmsPerm) "Granted" else "Not granted"}", style = MaterialTheme.typography.bodySmall)
                        Text("READ_PHONE_STATE: ${if (hasPhonePerm) "Granted" else "Not granted"}", style = MaterialTheme.typography.bodySmall)
                        Button(
                            onClick = {
                                permLauncher.launch(
                                    arrayOf(
                                        Manifest.permission.SEND_SMS,
                                        Manifest.permission.READ_PHONE_STATE
                                    )
                                )
                            }
                        ) {
                            Text("Request Runtime Permissions")
                        }
                        if (sims.isEmpty()) {
                            Text(
                                "No active SIM detected (or READ_PHONE_STATE not granted).",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        } else {
                            sims.forEach { sim ->
                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        "Slot ${sim.slotIndex}: ${sim.carrierLabel} (${sim.maskedMsisdn})",
                                        style = MaterialTheme.typography.bodySmall
                                    )
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

            statusMessage?.let { msg ->
                item {
                    Text(msg, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodySmall)
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Local Job Journal (${recentJobs.size})", style = MaterialTheme.typography.titleMedium)
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
                    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("${entry.jobId} · ${entry.state}", style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "To ${entry.destinationMasked} · Slot ${entry.simSlot}" +
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
