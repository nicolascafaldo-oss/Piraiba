package com.example.capture

import android.content.Context
import android.net.wifi.WifiManager
import com.example.model.CaptureSource
import com.example.model.PacketDirection
import com.example.vpn.PacketChecksumUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Local Wi-Fi LAN multicast/broadcast listener using WifiManager.MulticastLock.
 *
 * Joins standard unprivileged local discovery groups (mDNS 224.0.0.251:5353 and
 * SSDP/UPnP 239.255.255.250:1900) on active Wi-Fi/LAN interfaces and reconstructs
 * genuine IPv4/UDP frames into CaptureRepository for full dissection & .pcap export.
 */
object LanMulticastSniffer {

    const val MDNS_GROUP = "224.0.0.251"
    const val MDNS_PORT = 5353
    const val SSDP_GROUP = "239.255.255.250"
    const val SSDP_PORT = 1900
    const val LLMNR_GROUP = "224.0.0.252"
    const val LLMNR_PORT = 5355
    const val WSD_PORT = 3702
    const val NBNS_PORT = 137

    private val running = AtomicBoolean(false)
    private val ipIdSeq = AtomicInteger(1000)

    private val _isListening = MutableStateFlow(false)
    val isListening: StateFlow<Boolean> = _isListening.asStateFlow()

    private val _lanPacketCount = MutableStateFlow(0L)
    val lanPacketCount: StateFlow<Long> = _lanPacketCount.asStateFlow()

    private var multicastLock: WifiManager.MulticastLock? = null
    private val activeSockets = mutableListOf<DatagramSocket>()
    private val listenerThreads = mutableListOf<Thread>()
    @Volatile
    private var activeProtector: ((DatagramSocket) -> Boolean)? = null

    fun start(
        context: Context,
        socketProtector: ((DatagramSocket) -> Boolean)?
    ) {
        activeProtector = socketProtector
        if (!running.compareAndSet(false, true)) {
            return
        }

        runCatching {
            val wifiManager = context.applicationContext.getSystemService(WifiManager::class.java)
            if (wifiManager != null) {
                val lock = wifiManager.createMulticastLock("piraiba_lan_multicast").apply {
                    setReferenceCounted(false)
                    acquire()
                }
                multicastLock = lock
            }
        }

        _isListening.value = true
        synchronized(listenerThreads) {
            listenerThreads.clear()
            listenerThreads += Thread(
                { runGroupListener(MDNS_GROUP, MDNS_PORT, socketProtector) },
                "Piraiba-LAN-mDNS"
            ).apply { start() }

            listenerThreads += Thread(
                { runGroupListener(SSDP_GROUP, SSDP_PORT, socketProtector) },
                "Piraiba-LAN-SSDP"
            ).apply { start() }

            listenerThreads += Thread(
                { runGroupListener(LLMNR_GROUP, LLMNR_PORT, socketProtector) },
                "Piraiba-LAN-LLMNR"
            ).apply { start() }

            listenerThreads += Thread(
                { runGroupListener(SSDP_GROUP, WSD_PORT, socketProtector) },
                "Piraiba-LAN-WSD"
            ).apply { start() }

            listenerThreads += Thread(
                { runUdpBroadcastListener(NBNS_PORT, socketProtector) },
                "Piraiba-LAN-NBNS"
            ).apply { start() }
        }
    }

    fun restartIfRunning(
        context: Context,
        socketProtector: ((DatagramSocket) -> Boolean)?
    ) {
        activeProtector = socketProtector
        if (running.get()) {
            stop(resetCount = false)
            start(context, socketProtector)
        }
    }

    fun stop(resetCount: Boolean = false) {
        running.set(false)
        _isListening.value = false
        if (resetCount) {
            _lanPacketCount.value = 0L
        }
        synchronized(activeSockets) {
            activeSockets.forEach { sock -> runCatching { sock.close() } }
            activeSockets.clear()
        }
        synchronized(listenerThreads) {
            listenerThreads.forEach { it.interrupt() }
            listenerThreads.clear()
        }
        runCatching {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
            }
        }
        multicastLock = null
    }

    fun resetCounter() {
        _lanPacketCount.value = 0L
    }

    /**
     * Sends real mDNS PTR (_services._dns-sd._udp.local & _http._tcp.local) and
     * SSDP M-SEARCH multicast queries on local Wi-Fi interfaces to elicit live LAN responses.
     */
    fun sendDiscoverySweep(socketProtector: ((DatagramSocket) -> Boolean)? = activeProtector): String {
        val lanInterfaces = findMulticastInterfaces()
        var sentCount = 0

        val mdnsServicesQuery = buildMdnsPtrQuery(listOf("_services", "_dns-sd", "_udp", "local"))
        val mdnsHttpQuery = buildMdnsPtrQuery(listOf("_http", "_tcp", "local"))
        val ssdpQuery = (
            "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 2\r\n" +
                "ST: ssdp:all\r\n\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)

        val mdnsGroup = InetAddress.getByName(MDNS_GROUP)
        val ssdpGroup = InetAddress.getByName(SSDP_GROUP)

        MulticastSocket().use { sock ->
            socketProtector?.invoke(sock)
            sock.timeToLive = 255
            if (lanInterfaces.isEmpty()) {
                runCatching {
                    sock.send(DatagramPacket(mdnsServicesQuery, mdnsServicesQuery.size, mdnsGroup, MDNS_PORT))
                    sentCount++
                }
                runCatching {
                    sock.send(DatagramPacket(mdnsHttpQuery, mdnsHttpQuery.size, mdnsGroup, MDNS_PORT))
                    sentCount++
                }
                runCatching {
                    sock.send(DatagramPacket(ssdpQuery, ssdpQuery.size, ssdpGroup, SSDP_PORT))
                    sentCount++
                }
            } else {
                for (netIf in lanInterfaces) {
                    runCatching {
                        sock.networkInterface = netIf
                        sock.send(DatagramPacket(mdnsServicesQuery, mdnsServicesQuery.size, mdnsGroup, MDNS_PORT))
                        sentCount++
                    }
                    runCatching {
                        sock.networkInterface = netIf
                        sock.send(DatagramPacket(mdnsHttpQuery, mdnsHttpQuery.size, mdnsGroup, MDNS_PORT))
                        sentCount++
                    }
                    runCatching {
                        sock.networkInterface = netIf
                        sock.send(DatagramPacket(ssdpQuery, ssdpQuery.size, ssdpGroup, SSDP_PORT))
                        sentCount++
                    }
                }
            }
        }

        return if (sentCount > 0) {
            "Sent $sentCount real mDNS/SSDP LAN discovery sweeps on Wi-Fi"
        } else {
            "No active Wi-Fi multicast interface available for LAN sweep"
        }
    }

    private fun runGroupListener(
        groupIp: String,
        port: Int,
        socketProtector: ((DatagramSocket) -> Boolean)?
    ) {
        var socket: MulticastSocket? = null
        try {
            val groupAddr = InetAddress.getByName(groupIp)
            socket = MulticastSocket(null).apply {
                reuseAddress = true
                soTimeout = 1000
                bind(InetSocketAddress(port))
            }
            socketProtector?.invoke(socket)
            synchronized(activeSockets) { activeSockets.add(socket) }

            val interfaces = findMulticastInterfaces()
            var joinedAny = false
            for (netIf in interfaces) {
                runCatching {
                    socket.joinGroup(InetSocketAddress(groupAddr, port), netIf)
                    joinedAny = true
                }
            }
            if (!joinedAny) {
                @Suppress("DEPRECATION")
                runCatching { socket.joinGroup(groupAddr) }
            }

            val buf = ByteArray(4096)
            val dstIpBytes = groupAddr.address
            while (running.get() && !socket.isClosed) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(packet)
                    val senderAddr = packet.address as? Inet4Address ?: continue
                    val len = packet.length
                    if (len <= 0) continue
                    val payload = packet.data.copyOfRange(packet.offset, packet.offset + len)
                    val frame = buildLanUdpFrame(
                        srcIp = senderAddr.address,
                        dstIp = dstIpBytes,
                        srcPort = packet.port,
                        dstPort = port,
                        payload = payload,
                        ipId = ipIdSeq.getAndIncrement() and 0xFFFF
                    )
                    _lanPacketCount.value = _lanPacketCount.value + 1L
                    CaptureRepository.recordRawPacket(
                        rawBytes = frame,
                        direction = PacketDirection.INBOUND,
                        captureSource = CaptureSource.LAN_PROMISCUOUS
                    )
                } catch (_: SocketTimeoutException) {
                    // Periodic poll check for clean shutdown
                }
            }
        } catch (_: Exception) {
            // Port restricted by OS, closed, or network unavailable
        } finally {
            if (socket != null) {
                synchronized(activeSockets) { activeSockets.remove(socket) }
                runCatching { socket.close() }
            }
        }
    }

    private fun runUdpBroadcastListener(
        port: Int,
        socketProtector: ((DatagramSocket) -> Boolean)?
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                soTimeout = 1000
                bind(InetSocketAddress(port))
            }
            socketProtector?.invoke(socket)
            synchronized(activeSockets) { activeSockets.add(socket) }

            val buf = ByteArray(2048)
            val broadcastIpBytes = byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte())
            while (running.get() && !socket.isClosed) {
                val packet = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(packet)
                    val senderAddr = packet.address as? Inet4Address ?: continue
                    val len = packet.length
                    if (len <= 0) continue
                    val payload = packet.data.copyOfRange(packet.offset, packet.offset + len)
                    val frame = buildLanUdpFrame(
                        srcIp = senderAddr.address,
                        dstIp = broadcastIpBytes,
                        srcPort = packet.port,
                        dstPort = port,
                        payload = payload,
                        ipId = ipIdSeq.getAndIncrement() and 0xFFFF
                    )
                    _lanPacketCount.value = _lanPacketCount.value + 1L
                    CaptureRepository.recordRawPacket(
                        rawBytes = frame,
                        direction = PacketDirection.INBOUND,
                        captureSource = CaptureSource.LAN_PROMISCUOUS
                    )
                } catch (_: SocketTimeoutException) {
                    // Poll check
                }
            }
        } catch (_: Exception) {
            // Privileged port (<1024) on stock non-root Android or closed cleanly
        } finally {
            if (socket != null) {
                synchronized(activeSockets) { activeSockets.remove(socket) }
                runCatching { socket.close() }
            }
        }
    }

    private fun findMulticastInterfaces(): List<NetworkInterface> {
        val list = mutableListOf<NetworkInterface>()
        val all = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull() ?: return emptyList()
        while (all.hasMoreElements()) {
            val ni = all.nextElement()
            val nameLower = ni.name.lowercase()
            if (nameLower.startsWith("tun") || nameLower.startsWith("ppp") || nameLower.startsWith("rmnet")) {
                continue
            }
            val usable = runCatching {
                ni.isUp && !ni.isLoopback && !ni.isPointToPoint && ni.supportsMulticast() &&
                    ni.inetAddresses.asSequence().any { it is Inet4Address }
            }.getOrDefault(false)
            if (usable) {
                list.add(ni)
            }
        }
        return list.sortedByDescending { it.name.startsWith("wlan") || it.name.startsWith("eth") }
    }

    /**
     * Reconstructs a valid IPv4 + UDP frame with RFC 1071 header and pseudo-header checksums
     * so LAN multicast datagrams integrate cleanly with PacketDissector and PCAP export.
     */
    internal fun buildLanUdpFrame(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        ipId: Int = 1000
    ): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4) { "IPv4 addresses must be 4 bytes" }
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)

        pkt[0] = 0x45.toByte()
        pkt[1] = 0x00
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[4] = ((ipId ushr 8) and 0xFF).toByte()
        pkt[5] = (ipId and 0xFF).toByte()
        pkt[6] = 0x00
        pkt[7] = 0x00
        pkt[8] = 255.toByte()
        pkt[9] = 17.toByte() // UDP
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)

        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, 28, payload.size)
        }

        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 17, udpLen)
        return pkt
    }

    private fun buildMdnsPtrQuery(labels: List<String>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x00); out.write(0x00) // mDNS Transaction ID = 0
        out.write(0x00); out.write(0x00) // Standard Query
        out.write(0x00); out.write(0x01) // QDCOUNT = 1
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        out.write(0x00); out.write(0x00)
        for (label in labels) {
            val bytes = label.toByteArray(StandardCharsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0x00)
        out.write(0x00); out.write(0x0C) // QTYPE = PTR (12)
        out.write(0x00); out.write(0x01) // QCLASS = IN (1)
        return out.toByteArray()
    }
}
