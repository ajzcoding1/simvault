# SimVault Android Gateway ProGuard / R8 rules
-keep class com.simvault.gateway.BuildConfig { *; }
-keep class com.simvault.gateway.data.** { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keepattributes Signature,InnerClasses,EnclosingMethod

# AndroidX Security Crypto / Tink
-keepclassmembers class * extends com.google.crypto.tink.shaded.protobuf.GeneratedMessageLite { *; }
