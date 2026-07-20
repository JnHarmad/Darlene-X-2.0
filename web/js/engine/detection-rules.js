/**
 * Darlene-X_2.0 detection rules
 * Ported from Understanding_logical_flow/values.py (SUSPICIOUS_APIS)
 * plus capability heuristics used by the offline browser engine.
 *
 * No network I/O. Rules stay in-memory on the analyst machine.
 */
(function (global) {
  'use strict';

  /**
   * Exact / near-exact DEX string signatures from the reference analyzer.
   * Smali-style type descriptors + common Java method names.
   */
  const REFERENCE_SUSPICIOUS_APIS = [
    { needle: 'Ljava/lang/reflect/Method;->invoke', sev: 'high', msg: 'Reflection Method.invoke — dynamic dispatch / evasion', cat: 'Reflection' },
    { needle: 'Ljavax/crypto/Cipher;->doFinal', sev: 'medium', msg: 'Cipher.doFinal — crypto payload encrypt/decrypt', cat: 'Crypto' },
    { needle: 'Ljava/lang/Runtime;->exec', sev: 'high', msg: 'Runtime.exec — shell command execution', cat: 'RCE' },
    { needle: 'Ljava/lang/System;->load', sev: 'medium', msg: 'System.load — native library load from path', cat: 'Native' },
    { needle: 'Ldalvik/system/DexClassLoader;->loadClass', sev: 'high', msg: 'DexClassLoader.loadClass — dynamic code loading / dropper', cat: 'Dropper' },
    { needle: 'Ljava/lang/System;->loadLibrary', sev: 'medium', msg: 'System.loadLibrary — native .so load', cat: 'Native' },
    { needle: 'Ljava/net/URL;->openConnection', sev: 'medium', msg: 'URL.openConnection — network exfil / C2 fetch', cat: 'Network' },
    { needle: 'Landroid/hardware/Camera;->open', sev: 'high', msg: 'Camera.open — camera access', cat: 'Spyware' },
    { needle: 'Landroid/hardware/Camera;->takePicture', sev: 'high', msg: 'Camera.takePicture — silent photo capture', cat: 'Spyware' },
    { needle: 'Landroid/telephony/SmsManager;->sendMultipartTextMessage', sev: 'high', msg: 'SmsManager.sendMultipartTextMessage — SMS fraud', cat: 'Fraud' },
    { needle: 'Landroid/telephony/SmsManager;->sendTextMessage', sev: 'high', msg: 'SmsManager.sendTextMessage — SMS fraud / C2', cat: 'Fraud' },
    { needle: 'Landroid/media/AudioRecord;->startRecording', sev: 'high', msg: 'AudioRecord.startRecording — mic spyware', cat: 'Spyware' },
    { needle: 'Landroid/telephony/TelephonyManager;->getCellLocation', sev: 'high', msg: 'TelephonyManager.getCellLocation — cell triangulation', cat: 'Tracking' },
    { needle: 'Lcom/google/android/gms/location/LocationClient;->getLastLocation', sev: 'medium', msg: 'GMS LocationClient.getLastLocation', cat: 'Tracking' },
    { needle: 'Landroid/location/LocationManager;->getLastKnownLocation', sev: 'medium', msg: 'LocationManager.getLastKnownLocation', cat: 'Tracking' },
    { needle: 'Landroid/telephony/TelephonyManager;->getDeviceId', sev: 'high', msg: 'TelephonyManager.getDeviceId — IMEI harvest', cat: 'Spyware' },
    { needle: 'Landroid/content/pm/PackageManager;->getInstalledApplications', sev: 'medium', msg: 'PackageManager.getInstalledApplications — app recon', cat: 'Recon' },
    { needle: 'Landroid/content/pm/PackageManager;->getInstalledPackages', sev: 'medium', msg: 'PackageManager.getInstalledPackages — app recon', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getLine1Number', sev: 'high', msg: 'TelephonyManager.getLine1Number — phone number harvest', cat: 'Spyware' },
    { needle: 'Landroid/telephony/TelephonyManager;->getNetworkOperator', sev: 'medium', msg: 'TelephonyManager.getNetworkOperator', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getNetworkOperatorName', sev: 'medium', msg: 'TelephonyManager.getNetworkOperatorName', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getNetworkCountryIso', sev: 'low', msg: 'TelephonyManager.getNetworkCountryIso', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getSimOperator', sev: 'medium', msg: 'TelephonyManager.getSimOperator', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getSimOperatorName', sev: 'medium', msg: 'TelephonyManager.getSimOperatorName', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getSimCountryIso', sev: 'low', msg: 'TelephonyManager.getSimCountryIso', cat: 'Recon' },
    { needle: 'Landroid/telephony/TelephonyManager;->getSimSerialNumber', sev: 'high', msg: 'TelephonyManager.getSimSerialNumber — SIM serial harvest', cat: 'Spyware' },
    { needle: 'Lorg/apache/http/impl/client/DefaultHttpClient;->execute', sev: 'medium', msg: 'Apache DefaultHttpClient.execute — legacy HTTP client', cat: 'Network' },
    // Additional high-signal APIs used by banking / spyware families
    { needle: 'Landroid/accessibilityservice/AccessibilityService', sev: 'high', msg: 'AccessibilityService — keylogging / overlay abuse', cat: 'Spyware' },
    { needle: 'Landroid/app/admin/DevicePolicyManager', sev: 'high', msg: 'DevicePolicyManager — lock/wipe / ransomware path', cat: 'Ransomware' },
    { needle: 'Ldalvik/system/InMemoryDexClassLoader', sev: 'high', msg: 'InMemoryDexClassLoader — memory-only payload load', cat: 'Dropper' },
    { needle: 'Ldalvik/system/PathClassLoader', sev: 'medium', msg: 'PathClassLoader — secondary DEX load path', cat: 'Dropper' },
    { needle: 'Landroid/webkit/WebView;->addJavascriptInterface', sev: 'high', msg: 'WebView.addJavascriptInterface — JS bridge RCE class', cat: 'WebView Attack' },
    { needle: 'Ljavax/net/ssl/X509TrustManager', sev: 'high', msg: 'Custom X509TrustManager — possible SSL pinning bypass', cat: 'MITM Risk' },
    { needle: 'Landroid/content/ClipboardManager', sev: 'high', msg: 'ClipboardManager — clipjack / crypto swap', cat: 'Fraud' },
  ];

  /** Convert reference needles into regex DEX_PATTERNS entries. */
  function toDexPatterns(list) {
    return list.map((item) => ({
      p: new RegExp(item.needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'),
      sev: item.sev,
      msg: item.msg,
      cat: item.cat,
      source: 'reference',
    }));
  }

  /**
   * Dangerous permission short-names (android.permission.* suffix).
   * Used for combo / risk scoring when manifest strings are thin.
   */
  const DANGEROUS_PERMISSION_HINTS = [
    'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CALL_LOG', 'CALL_PHONE',
    'PROCESS_OUTGOING_CALLS', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION',
    'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'GET_ACCOUNTS',
    'READ_PHONE_STATE', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
    'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE',
    'BIND_DEVICE_ADMIN', 'WRITE_SECURE_SETTINGS', 'READ_LOGS',
  ];

  global.DarleneRules = {
    REFERENCE_SUSPICIOUS_APIS,
    EXTRA_DEX_PATTERNS: toDexPatterns(REFERENCE_SUSPICIOUS_APIS),
    DANGEROUS_PERMISSION_HINTS,
    version: '2.0.0',
  };
})(typeof window !== 'undefined' ? window : globalThis);
