package com.example.capture

import com.example.dissector.PacketDissector
import com.example.model.CapturedPacket
import com.example.model.PacketDirection
import com.example.model.ProbeType
import com.example.model.ThroughputPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Thread-safe singleton repository holding live captured packets, throughput telemetry,
 * and VPN capture state shared between PacketCaptureVpnService and the Compose UI.
 */
object CaptureRepository {

    private const val MAX_BUFFERED_PACKETS = 4000
    private const val THROUGHPUT_WINDOW_SEC = 60

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val bufferLock = Any()
    private val packetBuffer = ArrayDeque<CapturedPacket>(MAX_BUFFERED_PACKETS)
    private val nextPacketId = AtomicLong(0L)
    private val dirty = AtomicBoolean(false)

    private val throughputLock = Any()
    private val secondBuckets = LinkedHashMap<Long, MutableThroughputBucket>()

    private data class MutableThroughputBucket(
        var packets: Int = 0,
        var bytesOut: Long = 0L,
        var bytesIn: Long = 0L
    )

    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()

    private val _captureStartTimeMs = MutableStateFlow<Long?>(null)
    val captureStartTimeMs: StateFlow<Long?> = _captureStartTimeMs.asStateFlow()

    private val _packets = MutableStateFlow<List<CapturedPacket>>(emptyList())
    val packets: StateFlow<List<CapturedPacket>> = _packets.asStateFlow()

    private val _totalPacketCount = MutableStateFlow(0L)
    val totalPacketCount: StateFlow<Long> = _totalPacketCount.asStateFlow()

    private val _totalBytes = MutableStateFlow(0L)
    val totalBytes: StateFlow<Long> = _totalBytes.asStateFlow()

    private val _throughputHistory = MutableStateFlow<List<ThroughputPoint>>(emptyList())
    val throughputHistory: StateFlow<List<ThroughputPoint>> = _throughputHistory.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    init {
        scope.launch {
            while (isActive) {
                if (dirty.compareAndSet(true, false)) {
                    flushToStateFlows()
                } else if (_isCapturing.value) {
                    updateThroughputOnly()
                }
                delay(120L)
            }
        }
    }

    fun onCaptureStarted() {
        val now = System.currentTimeMillis()
        if (_captureStartTimeMs.value == null) {
            _captureStartTimeMs.value = now
        }
        _isCapturing.value = true
        _statusMessage.value = "Local VPN tunnel active on tun0 (10.1.10.1)"
    }

    fun onCaptureStopped(reason: String? = null) {
        _isCapturing.value = false
        if (dirty.compareAndSet(true, false)) {
            flushToStateFlows()
        }
        _statusMessage.value = reason
    }

    fun clearStatusMessage() {
        _statusMessage.value = null
    }

    fun recordRawPacket(rawBytes: ByteArray, direction: PacketDirection) {
        if (rawBytes.isEmpty()) return
        val now = System.currentTimeMillis()
        val start = _captureStartTimeMs.value ?: now.also { _captureStartTimeMs.value = it }
        val relMs = (now - start).coerceAtLeast(0L)
        val id = nextPacketId.incrementAndGet()

        val dissected = PacketDissector.dissect(
            id = id,
            rawBytes = rawBytes,
            timestampMs = now,
            relativeTimeMs = relMs,
            direction = direction
        )

        synchronized(bufferLock) {
            if (packetBuffer.size >= MAX_BUFFERED_PACKETS) {
                packetBuffer.removeFirst()
            }
            packetBuffer.addLast(dissected)
        }
        DnsResolutionCache.ingestPacket(dissected)
        AlertMonitor.evaluatePacket(dissected)

        _totalPacketCount.value = id
        _totalBytes.value += rawBytes.size.toLong()

        val sec = now / 1000L
        synchronized(throughputLock) {
            val bucket = secondBuckets.getOrPut(sec) { MutableThroughputBucket() }
            bucket.packets += 1
            if (direction == PacketDirection.OUTBOUND) {
                bucket.bytesOut += rawBytes.size.toLong()
            } else {
                bucket.bytesIn += rawBytes.size.toLong()
            }
            val cutoff = sec - THROUGHPUT_WINDOW_SEC - 5
            val iter = secondBuckets.keys.iterator()
            while (iter.hasNext()) {
                if (iter.next() < cutoff) iter.remove()
            }
        }

        dirty.set(true)
    }

    fun replaceWithImportedPackets(imported: List<CapturedPacket>) {
        synchronized(bufferLock) {
            packetBuffer.clear()
            for (pkt in imported.takeLast(MAX_BUFFERED_PACKETS)) {
                packetBuffer.addLast(pkt)
            }
        }
        nextPacketId.set(imported.lastOrNull()?.id ?: 0L)
        _totalPacketCount.value = imported.size.toLong()
        _totalBytes.value = imported.sumOf { it.length.toLong() }
        _captureStartTimeMs.value = imported.firstOrNull()?.timestampMs
        synchronized(throughputLock) {
            secondBuckets.clear()
        }
        val limited = imported.takeLast(MAX_BUFFERED_PACKETS)
        _packets.value = limited
        _throughputHistory.value = emptyList()
        DnsResolutionCache.clear()
        DnsResolutionCache.ingestPackets(limited)
        AlertMonitor.resetTrackingState()
        limited.forEach { AlertMonitor.evaluatePacket(it) }
    }

    fun clearCapture() {
        synchronized(bufferLock) {
            packetBuffer.clear()
        }
        synchronized(throughputLock) {
            secondBuckets.clear()
        }
        nextPacketId.set(0L)
        _totalPacketCount.value = 0L
        _totalBytes.value = 0L
        _captureStartTimeMs.value = if (_isCapturing.value) System.currentTimeMillis() else null
        _packets.value = emptyList()
        _throughputHistory.value = emptyList()
        dirty.set(false)
        DnsResolutionCache.clear()
        AlertMonitor.clearAlerts()
    }

    fun snapshotAllPackets(): List<CapturedPacket> = synchronized(bufferLock) {
        packetBuffer.toList()
    }

    private fun flushToStateFlows() {
        val snapshot = synchronized(bufferLock) { packetBuffer.toList() }
        _packets.value = snapshot
        updateThroughputOnly()
    }

    private fun updateThroughputOnly() {
        val nowSec = System.currentTimeMillis() / 1000L
        val points = synchronized(throughputLock) {
            ((nowSec - 29)..nowSec).map { sec ->
                val b = secondBuckets[sec]
                ThroughputPoint(
                    bucketSecond = sec,
                    packetsPerSec = b?.packets ?: 0,
                    bytesOut = b?.bytesOut ?: 0L,
                    bytesIn = b?.bytesIn ?: 0L
                )
            }
        }
        _throughputHistory.value = points
    }

    /**
     * Executes a genuine unprotected network diagnostic probe (DNS, HTTP, or TLS) so
     * traffic routes through the active VPN TUN interface and appears live in the packet list.
     */
    suspend fun sendDiagnosticProbe(type: ProbeType): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            when (type) {
                ProbeType.DNS_QUERY -> {
                    val queryBytes = buildDnsQueryPacket("example.com")
                    DatagramSocket().use { socket ->
                        socket.soTimeout = 3000
                        val target = InetAddress.getByName("8.8.8.8")
                        socket.send(DatagramPacket(queryBytes, queryBytes.size, target, 53))
                        val respBuf = ByteArray(512)
                        val respPkt = DatagramPacket(respBuf, respBuf.size)
                        socket.receive(respPkt)
                        "DNS A-record response received from 8.8.8.8 (${respPkt.length} bytes)"
                    }
                }
                ProbeType.HTTP_GET -> {
                    Socket().use { socket ->
                        socket.soTimeout = 4000
                        socket.connect(InetSocketAddress("example.com", 80), 4000)
                        val req = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Piraiba/1.0\r\nConnection: close\r\n\r\n"
                        socket.getOutputStream().write(req.toByteArray(StandardCharsets.US_ASCII))
                        socket.getOutputStream().flush()
                        val buf = ByteArray(1024)
                        val read = socket.getInputStream().read(buf)
                        val statusLine = if (read > 0) {
                            String(buf, 0, read, StandardCharsets.US_ASCII).lineSequence().firstOrNull().orEmpty()
                        } else {
                            "Connection closed"
                        }
                        "HTTP response: $statusLine"
                    }
                }
                ProbeType.HTTPS_TLS -> {
                    val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                    (factory.createSocket() as SSLSocket).use { sslSocket ->
                        sslSocket.soTimeout = 4000
                        sslSocket.connect(InetSocketAddress("example.com", 443), 4000)
                        sslSocket.startHandshake()
                        val session = sslSocket.session
                        "TLS handshake succeeded: ${session.protocol} (${session.cipherSuite})"
                    }
                }
            }
        }
    }

    private fun buildDnsQueryPacket(domain: String): ByteArray {
        val out = ByteArrayOutputStream()
        // Transaction ID (0x4A 0x54)
        out.write(0x4A)
        out.write(0x54)
        // Flags: Standard Query, Recursion Desired (0x0100)
        out.write(0x01)
        out.write(0x00)
        // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        for (label in domain.split('.')) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00) // root terminator
        out.write(0x00); out.write(0x01) // QTYPE = A (1)
        out.write(0x00); out.write(0x01) // QCLASS = IN (1)
        return out.toByteArray()
    }
}
