package com.example.capture

import com.example.model.CapturedPacket
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.ResolutionSource
import com.example.model.ResolvedHost
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Thread-safe DNS resolution cache that:
 * 1) Passively extracts IP-to-domain mappings from captured DNS A/AAAA/PTR answers, TLS SNI, and HTTP Host headers.
 * 2) Actively resolves unresolved public IPs via protected out-of-band UDP PTR queries (avoiding TUN capture loops)
 *    when the VPN is running, or standard system InetAddress reverse lookup when inspecting offline PCAPs.
 */
object DnsResolutionCache {

    private const val NEGATIVE_RETRY_MS = 60_000L
    private const val PTR_TIMEOUT_MS = 1500
    private const val WORKER_COUNT = 3
    private const val MAX_CACHED_HOSTS = 2000

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val txIdCounter = AtomicInteger(0x2100)

    private val cache = ConcurrentHashMap<String, ResolvedHost>()
    private val lookupCooldownUntil = ConcurrentHashMap<String, Long>()
    private val ptrQueue = Channel<String>(capacity = 128)

    @Volatile
    private var socketProtector: ((DatagramSocket) -> Boolean)? = null

    @Volatile
    private var autoPtrEnabled: Boolean = true

    private val _resolvedHosts = MutableStateFlow<Map<String, ResolvedHost>>(emptyMap())
    val resolvedHosts: StateFlow<Map<String, ResolvedHost>> = _resolvedHosts.asStateFlow()

    init {
        repeat(WORKER_COUNT) {
            scope.launch {
                for (ip in ptrQueue) {
                    performPtrLookup(ip)
                }
            }
        }
    }

    fun setSocketProtector(protector: ((DatagramSocket) -> Boolean)?) {
        socketProtector = protector
    }

    fun setAutoPtrEnabled(enabled: Boolean) {
        autoPtrEnabled = enabled
    }

    fun ingestPackets(packets: List<CapturedPacket>) {
        var changed = false
        for (pkt in packets) {
            if (ingestPacketInternal(pkt)) {
                changed = true
            }
        }
        if (changed) {
            publishSnapshot()
        }
    }

    fun ingestPacket(packet: CapturedPacket) {
        if (ingestPacketInternal(packet)) {
            publishSnapshot()
        }
    }

    private fun ingestPacketInternal(packet: CapturedPacket): Boolean {
        var changed = false

        // 1. High-confidence passive mappings directly from dissected DNS A/AAAA/PTR answers
        for (mapping in packet.dnsMappings) {
            if (putMappingInternal(mapping.ip, mapping.domain, ResolutionSource.DNS_ANSWER, packet.timestampMs)) {
                changed = true
            }
        }

        // 2. Passive mappings from TLS SNI or HTTP Host headers to the remote IP
        val remoteIp = if (packet.direction == PacketDirection.OUTBOUND) packet.dstIp else packet.srcIp
        val hostCandidate = packet.hostOrSni?.let { normalizeHostname(it) }
        if (!hostCandidate.isNullOrBlank()) {
            val source = when (packet.protocol) {
                ProtocolType.TLS -> ResolutionSource.TLS_SNI
                ProtocolType.HTTP -> ResolutionSource.HTTP_HOST
                else -> null
            }
            if (source != null && putMappingInternal(remoteIp, hostCandidate, source, packet.timestampMs)) {
                changed = true
            }
        }

        // 3. Queue asynchronous reverse PTR lookup for unresolved public endpoints
        if (autoPtrEnabled) {
            maybeEnqueuePtr(packet.srcIp)
            maybeEnqueuePtr(packet.dstIp)
        }

        return changed
    }

    fun putMapping(
        ip: String,
        domain: String,
        source: ResolutionSource,
        timestampMs: Long = System.currentTimeMillis()
    ) {
        if (putMappingInternal(ip, domain, source, timestampMs)) {
            publishSnapshot()
        }
    }

    private fun putMappingInternal(
        ip: String,
        rawDomain: String,
        source: ResolutionSource,
        timestampMs: Long
    ): Boolean {
        if (!isResolvablePublicIp(ip)) return false
        val domain = normalizeHostname(rawDomain) ?: return false
        if (domain.equals(ip, ignoreCase = true)) return false

        if (cache.size >= MAX_CACHED_HOSTS && !cache.containsKey(ip)) {
            // Trim oldest PTR entries first if cache grows very large
            val ptrKey = cache.entries
                .filter { it.value.source == ResolutionSource.REVERSE_PTR }
                .minByOrNull { it.value.updatedAtMs }
                ?.key
                ?: cache.keys.firstOrNull()
            if (ptrKey != null) cache.remove(ptrKey)
        }

        var updated = false
        cache.compute(ip) { _, existing ->
            if (existing == null || source.priority >= existing.source.priority) {
                if (existing == null || existing.domain != domain || existing.source != source) {
                    updated = true
                }
                ResolvedHost(
                    ip = ip,
                    domain = domain,
                    source = source,
                    updatedAtMs = timestampMs
                )
            } else {
                existing
            }
        }
        return updated
    }

    fun clear() {
        cache.clear()
        lookupCooldownUntil.clear()
        _resolvedHosts.value = emptyMap()
    }

    private fun publishSnapshot() {
        _resolvedHosts.value = HashMap(cache)
    }

    private fun maybeEnqueuePtr(ip: String) {
        if (!isResolvablePublicIp(ip)) return
        if (cache.containsKey(ip)) return
        val now = System.currentTimeMillis()
        val cooldown = lookupCooldownUntil[ip]
        if (cooldown != null && now < cooldown) return
        lookupCooldownUntil[ip] = now + NEGATIVE_RETRY_MS
        ptrQueue.trySend(ip)
    }

    private fun performPtrLookup(ip: String) {
        if (!autoPtrEnabled || cache.containsKey(ip) || !isResolvablePublicIp(ip)) return
        val protector = socketProtector
        val resolved = if (protector != null) {
            queryPtrOverProtectedUdp(ip, protector)
        } else {
            runCatching {
                val host = InetAddress.getByName(ip).canonicalHostName
                if (host.isNotBlank() && host != ip && !isNumericIp(host)) host else null
            }.getOrNull()
        }
        if (!resolved.isNullOrBlank()) {
            if (putMappingInternal(ip, resolved, ResolutionSource.REVERSE_PTR, System.currentTimeMillis())) {
                publishSnapshot()
            }
        }
    }

    private fun queryPtrOverProtectedUdp(
        ip: String,
        protector: (DatagramSocket) -> Boolean
    ): String? {
        val txId = txIdCounter.incrementAndGet() and 0xFFFF
        val queryBytes = buildPtrQueryPacket(ip, txId) ?: return null
        return runCatching {
            DatagramSocket().use { socket ->
                if (!protector(socket)) return@runCatching null
                socket.soTimeout = PTR_TIMEOUT_MS
                val dnsServer = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))
                socket.send(DatagramPacket(queryBytes, queryBytes.size, dnsServer, 53))
                val buf = ByteArray(512)
                val resp = DatagramPacket(buf, buf.size)
                socket.receive(resp)
                parsePtrResponse(buf.copyOf(resp.length), expectedTxId = txId)
            }
        }.getOrNull()
    }

    internal fun buildPtrQueryPacket(ip: String, txId: Int = 0x1234): ByteArray? {
        val arpaName = toArpaDomain(ip) ?: return null
        val out = ByteArrayOutputStream()
        out.write((txId ushr 8) and 0xFF)
        out.write(txId and 0xFF)
        // Standard recursive query (0x0100)
        out.write(0x01)
        out.write(0x00)
        // QDCOUNT = 1, AN/NS/AR = 0
        out.write(0x00); out.write(0x01)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)

        for (label in arpaName.split('.')) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            if (bytes.isEmpty() || bytes.size > 63) return null
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
        // QTYPE = PTR (12), QCLASS = IN (1)
        out.write(0x00); out.write(0x0C)
        out.write(0x00); out.write(0x01)
        return out.toByteArray()
    }

    internal fun parsePtrResponse(dnsBytes: ByteArray, expectedTxId: Int? = null): String? {
        if (dnsBytes.size < 12) return null
        val txId = u16(dnsBytes, 0)
        if (expectedTxId != null && txId != expectedTxId) return null
        val flags = u16(dnsBytes, 2)
        val isResponse = (flags and 0x8000) != 0
        val rcode = flags and 0x0F
        if (!isResponse || rcode != 0) return null

        val qdCount = u16(dnsBytes, 4)
        val anCount = u16(dnsBytes, 6)
        if (anCount == 0) return null

        var cursor = 12
        repeat(qdCount.coerceAtMost(4)) {
            val (_, nextPos) = readDnsName(dnsBytes, cursor) ?: return null
            if (nextPos + 4 > dnsBytes.size) return null
            cursor = nextPos + 4
        }

        repeat(anCount.coerceAtMost(8)) {
            val (_, nextPos) = readDnsName(dnsBytes, cursor) ?: return null
            if (nextPos + 10 > dnsBytes.size) return null
            val rType = u16(dnsBytes, nextPos)
            val rdLen = u16(dnsBytes, nextPos + 8)
            val rDataStart = nextPos + 10
            val rDataEnd = (rDataStart + rdLen).coerceAtMost(dnsBytes.size)
            if (rType == 12 && rDataStart < rDataEnd) {
                val ptrTarget = readDnsName(dnsBytes, rDataStart)?.first
                if (!ptrTarget.isNullOrBlank() && ptrTarget != "<root>") {
                    return ptrTarget.trimEnd('.')
                }
            }
            cursor = rDataEnd
        }
        return null
    }

    internal fun toArpaDomain(ip: String): String? {
        val parts = ip.split('.')
        if (parts.size == 4) {
            val octets = parts.map { it.toIntOrNull() ?: return null }
            if (octets.any { it !in 0..255 }) return null
            return "${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}.in-addr.arpa"
        }
        return null
    }

    internal fun isResolvablePublicIp(ip: String): Boolean {
        if (ip.isBlank() || ip == "—") return false
        if (ip.contains(':')) {
            val lower = ip.lowercase()
            return lower != "::" &&
                lower != "::1" &&
                !lower.startsWith("fe80:") &&
                !lower.startsWith("fc") &&
                !lower.startsWith("fd") &&
                !lower.startsWith("ff")
        }
        val parts = ip.split('.')
        if (parts.size != 4) return false
        val a = parts[0].toIntOrNull() ?: return false
        val b = parts[1].toIntOrNull() ?: return false
        val c = parts[2].toIntOrNull() ?: return false
        val d = parts[3].toIntOrNull() ?: return false
        if (a !in 0..255 || b !in 0..255 || c !in 0..255 || d !in 0..255) return false

        return when {
            a == 0 -> false // 0.0.0.0/8
            a == 10 -> false // 10.0.0.0/8 (includes local tun0 10.1.10.1)
            a == 127 -> false // loopback
            a == 169 && b == 254 -> false // link-local
            a == 172 && b in 16..31 -> false // 172.16.0.0/12
            a == 192 && b == 168 -> false // 192.168.0.0/16
            a == 100 && b in 64..127 -> false // CGNAT 100.64.0.0/10
            a >= 224 -> false // multicast / reserved / broadcast
            else -> true
        }
    }

    private fun normalizeHostname(raw: String): String? {
        var cleaned = raw.trim().trimEnd('.')
        // Strip port suffix from HTTP Host headers (e.g. "api.example.com:8080")
        val colonIdx = cleaned.indexOf(':')
        if (colonIdx > 0 && !cleaned.contains('[')) {
            cleaned = cleaned.substring(0, colonIdx)
        }
        if (cleaned.isBlank() || cleaned == "<root>" || isNumericIp(cleaned)) return null
        return cleaned.lowercase()
    }

    private fun isNumericIp(value: String): Boolean {
        if (value.contains(':')) return true
        val parts = value.split('.')
        return parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
    }

    private fun readDnsName(raw: ByteArray, startPos: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var curr = startPos
        var jumped = false
        var returnPos = startPos
        var jumps = 0

        while (curr < raw.size && jumps < 12) {
            val len = raw[curr].toInt() and 0xFF
            if (len == 0) {
                if (!jumped) returnPos = curr + 1
                break
            }
            if ((len and 0xC0) == 0xC0) {
                if (curr + 1 >= raw.size) return null
                val ptr = ((len and 0x3F) shl 8) or (raw[curr + 1].toInt() and 0xFF)
                if (!jumped) returnPos = curr + 2
                jumped = true
                curr = ptr
                jumps++
                if (curr < 0 || curr >= raw.size) return null
                continue
            }
            val labelLen = len and 0x3F
            curr++
            if (curr + labelLen > raw.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(raw, curr, labelLen, StandardCharsets.US_ASCII))
            curr += labelLen
            if (!jumped) returnPos = curr
        }
        return (if (sb.isEmpty()) "<root>" else sb.toString()) to returnPos
    }

    private fun u16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
}
