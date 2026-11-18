# SimVault Android Gateway App

Complete Kotlin + Jetpack Compose Android Studio project (`minSdk 29` / Android 10+, `targetSdk 35` / Android 15) that pairs with your SimVault backend over HTTPS, polls leased SMS jobs, dispatches SMS via Android's native `SmsManager` using owner-granted runtime permissions and explicit SIM selection, and uploads carrier delivery receipts when available.

## Included Modules
- **Gradle & Build Configuration**: `settings.gradle.kts`, `build.gradle.kts`, `app/build.gradle.kts`, `gradle.properties`, `gradle/wrapper/gradle-wrapper.properties`, `app/proguard-rules.pro`.
- **Resources & Manifest**: `AndroidManifest.xml`, `res/values/strings.xml`, `res/values/themes.xml`, adaptive launcher icons (`mipmap-anydpi-v26` + `drawable`).
- **Security & Storage**: `SecureCredentialStore.kt` (`EncryptedSharedPreferences` + `MasterKey` AES-256-GCM) and `LocalJobJournal.kt` (restart-safe duplicate protection).
- **SMS Dispatch & Delivery Receipts**: `NativeSmsSender.kt` (Android 10–15 `SmsManager` compatibility, multipart handling, explicit `PendingIntent`) + `SmsDeliveryReceiver.kt` + `DeliveryReportWorker.kt`.
- **Background & Foreground Polling**: `GatewayPollWorker.kt` (15-min WorkManager periodic + immediate trigger + real `ConnectivityManager` state) + `BootCompletedReceiver.kt` + 10s foreground auto-poll inside `MainActivity.kt`.

## Build & Install in Android Studio
1. Open the `android-gateway/` folder in **Android Studio (Ladybug or newer)** with JDK 17.
2. Let Gradle sync (`AGP 8.5.2`, `Kotlin 2.0.20`, `Gradle 8.7`).
3. Click **Build > Build Bundle(s) / APK(s) > Build APK(s)** or **Run `app`** on a connected Android 10+ phone.
4. Grant `SEND_SMS` and `READ_PHONE_STATE` runtime permissions inside the app, select your SIM slot, and pair using a one-time token generated from **Gateway Devices** in the SimVault web dashboard.
5. Keep **Mock Mode** ON for safe API/queue testing without spending carrier SMS; turn **Mock Mode** OFF only when ready for live SIM dispatch.

> **Note on Google Play Policy**: Because `SEND_SMS` is restricted on public Google Play listings, distribute privately (sideload APK / internal enterprise track) strictly for owner-operated gateway devices.
