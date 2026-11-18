# AGENTS.md

## What this is
Single-module Android app (Gradle `:app`, Kotlin 2.2 / AGP 9.1.1 / Compose): "Piraíba" —
real-time packet capture over a local `VpnService`, protocol dissection, and PCAP
import/export. Fully on-device; no backend. `metadata.json` is AI Studio metadata,
not build input.

## Toolchain: not set up out of the box
- `gradlew` is **not committed** (only `gradle/wrapper/gradle-wrapper.properties`,
  Gradle 9.3.1). Use an installed Gradle 9.x, or generate the wrapper first
  (`gradle wrapper --gradle-version 9.3.1`).
- Building needs an Android SDK (compileSdk 36.1): set `ANDROID_HOME` or create
  `local.properties`. Neither exists in a fresh clone on this machine, and no
  `gradle` is on PATH — expect to install toolchain before any build/test runs.
- On this machine a working toolchain is already installed (state, not repo content):
  Gradle at `~/tools/gradle-9.3.1`, JDK at `~/tools/jdk-25` (system Java is JRE-only),
  Android SDK at `~/android-sdk` + `local.properties`, `debug.keystore` at repo root.
  Full test command: `JAVA_HOME=$HOME/tools/jdk-25 ~/tools/gradle-9.3.1/bin/gradle --no-daemon :app:testDebugUnitTest`.
- Debug signing needs `debug.keystore` at the repo root (gitignored, absent):
  create it with keytool, alias `androiddebugkey`, store/key password `android`.
  Release signing reads `KEYSTORE_PATH`, `STORE_PASSWORD`, `KEY_PASSWORD` env vars.
- Do not delete or restructure the `signingConfigs` / `buildTypes` signingConfig
  assignments in `app/build.gradle.kts` — comments there mark them as required by
  Android AI Studio.

## Commands
- `gradle :app:testDebugUnitTest` — JVM unit tests (includes Robolectric suite)
- `gradle :app:testDebugUnitTest --tests "com.example.PacketDissectorTest"` — one test class
- `gradle :app:lintDebug` — lint (`:app:assembleDebug` to build)
- `gradle :app:connectedDebugAndroidTest` — needs a connected device/emulator
- There is no CI; these are the only verification steps.

## Architecture (non-obvious)
- Flow: FOUR capture sources feed `capture/CaptureRepository` (global `object`
  singleton, StateFlow, 4000-packet ring buffer): (1) `vpn/PacketCaptureVpnService`
  (TUN + user-space TCP/UDP NAT forwarder, device traffic), (2)
  `capture/RootPromiscuousSniffer` (root `su`+`tcpdump` sandbox, AF_PACKET frames),
  (3) `capture/LanMulticastSniffer` (mDNS/SSDP/LLMNR/NBNS via WifiManager.MulticastLock),
  (4) PCAP import (`dissector/PcapCodec.readPcap`). From the repository →
  `viewmodel/WireTraceViewModel` → `ui/WireTraceApp` + `ui/screens/*`.
  No DI framework; the UI also reads `CaptureRepository` directly (status messages,
  clear, snapshots). Treat the singleton as the single seam between service and UI.
- Stop is a MASTER stop: `WireTraceApp.stopVpnService()` and the service's own
  `stopCapture()` (notification Stop action, onRevoke, onDestroy) each tear down ALL
  backends — root tcpdump, LAN listener, VPN tunnel. Keep it that way: stopping only
  the VPN leaves the other backends capturing with no notification.
- The VPN service must keep forwarding real traffic while capturing. Changes to
  `vpn/PacketChecksumUtils` or packet rewriting do not fail the build — they break
  live connectivity on device. `PacketChecksumUtilsTest` covers checksums deliberately
  (known vectors + pseudo-header validation + bounds guards); keep it green, and never
  "simplify" checksum/pseudo-header logic.
- `dissector/PacketDissector` (1.1k lines) parses protocols incl. DNS (uses
  `capture/DnsResolutionCache`); `dissector/DisplayFilterParser` implements the
  Wireshark-style filter bar (`http && port == 80`, `payload contains "..."`);
  `dissector/PcapCodec` is the share/import PCAP format (exported via FileProvider).
- PCAP export link-type policy: homogeneous captures keep their native link type;
  mixed captures (VPN raw-IP + root Ethernet) unify under LINKTYPE_ETHERNET with a
  synthesized 14-byte header (true ethertype, zeroed MACs) for non-Ethernet packets.
  Never go back to strip-to-RAW for mixed sets — it corrupts non-IP frames (ARP).
- Namespace `com.example` ≠ `applicationId com.aistudio.wiretrace.kqxmtb`. An
  instrumented test asserts `BuildConfig.APPLICATION_ID == packageName`; do not
  "fix" this mismatch by renaming the applicationId.
- Alerts: `capture/AlertMonitor` evaluates thresholds; `capture/AlertConfigStore`
  persists config in DataStore Preferences (`wiretrace_alert_config`) and posts
  notifications. Both are `object` singletons.

## Tests
- Plain JUnit (hand-built raw byte arrays — no emulator, no Robolectric; keep new
  dissector/checksum tests in this style so they stay fast and runnable):
  `PacketDissectorTest` (dissection, filters, fragments, PCAP round trip),
  `AlertMonitorTest` (thresholds, cooldowns), `LanMulticastSnifferTest`
  (frame builder + source filters), `RootPromiscuousAndResolutionTest`
  (mDNS/SSDP ingest, SLL/ARP, libpcap stream), `PacketChecksumUtilsTest`
  (RFC 1071 vectors + pseudo-header self-validation + bounds guards),
  `PcapCodecIntegrityTest` (export link-type policy, import direction inference),
  `CaptureRepositoryIntegrityTest` (id monotonicity across import/clear, counters).
- Tests share the singletons: reset global state via `DnsResolutionCache.clear()` /
  `CaptureRepository.clearCapture()` in `@Before`/`@After`, and disable active PTR
  lookups (`setAutoPtrEnabled(false)`) so unit tests never send real DNS queries.
- `ExampleRobolectricTest` pins `@Config(sdk = [36])` (first run downloads Robolectric
  android-all jars — needs network).

## Secrets / config
- Secrets come from `.env` (gitignored) via the Secrets Gradle Plugin, falling back
  to `.env.example`. `GEMINI_API_KEY` is commented out by default and unused in code.
- The google-services plugin tolerates a missing `google-services.json`
  (`googleServices.missing.passthrough=true`); Firebase dependencies are commented
  out in `app/build.gradle.kts`. Additions to `gradle/libs.versions.toml` are usually
  wired there first as commented-out lines — uncomment as a group, per the comments.
