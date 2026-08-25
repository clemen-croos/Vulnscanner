# Vulnscanner
VulnScanner is an academic mobile application security platform developed for the NIT3003 IT Capstone Project at Victoria University. It allows users to upload Android APK files and perform static analysis, dynamic analysis or both.

The static engine uses Androguard, pattern-based security rules, data-flow checks, entropy analysis and context-based false-positive filtering to inspect application code, permissions, secrets, cryptography, WebViews, native libraries and configuration risks without running the application.

The dynamic engine uses ADB and a dedicated Android emulator to install, launch and exercise the application while collecting evidence from runtime configuration, Logcat, application storage, debugging interfaces, Android AppOps, crashes and process diagnostics.

Findings are classified by severity, mapped to security categories, assigned risk scores and stored separately as static or dynamic results. Users can access the platform through a React web interface or an Expo React Native mobile application.

This project is intended only for educational testing and authorized security assessments.
