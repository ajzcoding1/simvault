# SimVault Android Gateway App

Complete Kotlin + Jetpack Compose Android Studio project (`minSdk 29` / Android 10+, `targetSdk 35` / Android 15) that pairs with your SimVault backend over HTTPS, polls leased SMS & OTP jobs in real time, dispatches SMS via Android's native `SmsManager` using owner-granted runtime permissions and explicit SIM slot selection, and uploads carrier delivery receipts.

## Included Modules
- **Gradle & Build Configuration**: `settings.gradle.kts`, `build.gradle.kts`, `app/build.gradle.kts`, `gradle.properties`, `gradle/wrapper/gradle-wrapper.properties`, `app/proguard-rules.pro`.
- **Resources & Manifest**: `AndroidManifest.xml`, `res/values/strings.xml`, `res/values/themes.xml`, adaptive launcher icons (`mipmap-anydpi-v26` + `drawable`).
- **Security & Storage (`data/`)**: `GatewayModels.kt`, `SecureCredentialStore.kt` (`EncryptedSharedPreferences` + `MasterKey` AES-256-GCM), and `LocalJobJournal.kt` (restart-safe duplicate protection & history).
- **Networking (`network/`)**: `SimVaultGatewayClient.kt` with pooled `OkHttpClient`, `/health` pre-flight check, pairing, heartbeats, job leasing, and delivery receipts.
- **SMS Dispatch & Delivery Receipts (`sms/`, `receiver/`, `worker/`)**: `NativeSmsSender.kt` (Android 10–15 `SmsManager` compatibility, multipart handling, carrier error mapping) + `SmsDeliveryReceiver.kt` + `DeliveryReportWorker.kt`.
- **Always-On Background Polling (`service/`, `worker/`)**: `GatewayForegroundService.kt` (5s live OTP polling with persistent low-priority notification and exponential backoff), `GatewayPollEngine.kt` (mutex-protected shared poll cycle), `GatewayPollWorker.kt` (15-min WorkManager fallback), and `BootCompletedReceiver.kt`.

## Build & Install in Android Studio
1. Open the `android-gateway/` folder in **Android Studio (Ladybug or newer)** with JDK 17.
2. Let Gradle sync (`AGP 8.5.2`, `Kotlin 2.0.20`, `Gradle 8.7`).
3. Click **Build > Build Bundle(s) / APK(s) > Build APK(s)** or **Run `app`** on a connected Android 10+ phone.
4. Tap **Grant Permissions** (`SEND_SMS`, `READ_PHONE_STATE`, and `POST_NOTIFICATIONS` on Android 13+) and tap **Unrestrict Battery** so the OS does not pause background OTP polling.
5. Tap **Test Server** to confirm HTTPS + PostgreSQL `/health`, then enter your one-time token from **Gateway Devices** in the SimVault web console and tap **Pair Device**.

> **Note on Google Play Policy**: Because `SEND_SMS` and `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` are restricted on public Google Play listings, distribute privately (sideload APK / internal enterprise track) strictly for owner-operated gateway devices.
