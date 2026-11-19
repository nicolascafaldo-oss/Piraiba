package com.example.dissector

import com.example.model.CapturedPacket
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Standard libpcap (.pcap) binary encoder & decoder supporting LINKTYPE_RAW (101),
 * LINKTYPE_ETHERNET (1), LINKTYPE_LINUX_SLL (113), and LINKTYPE_LINUX_SLL2 (276).
 * Exported files open natively in standard desktop packet analyzers and tcpdump.
 */
object PcapCodec {

    private const val PCAP_MAGIC_LE = 0xA1B2C3D4.toInt()
    private const val PCAP_MAGIC_BE = 0xD4C3B2A1.toInt()
    const val LINKTYPE_ETHERNET = 1
    const val LINKTYPE_RAW = 101
    const val LINKTYPE_LINUX_SLL = 113
    const val LINKTYPE_LINUX_SLL2 = 276

    fun linkLayerForPcapType(linkType: Int): LinkLayerType = when (linkType) {
        LINKTYPE_ETHERNET -> LinkLayerType.ETHERNET
        LINKTYPE_LINUX_SLL -> LinkLayerType.LINUX_SLL
        LINKTYPE_LINUX_SLL2 -> LinkLayerType.LINUX_SLL2
        else -> LinkLayerType.RAW_TUN
    }

    fun ipHeaderOffset(linkLayerType: LinkLayerType): Int = when (linkLayerType) {
        LinkLayerType.ETHERNET -> 14
        LinkLayerType.LINUX_SLL -> 16
        LinkLayerType.LINUX_SLL2 -> 20
        LinkLayerType.RAW_TUN -> 0
    }

    fun writePcap(packets: List<CapturedPacket>, outputStream: OutputStream) {
        // One link type per file. A homogeneous capture exports as its native link type
        // (byte-identical frames). A MIXED capture — e.g. device VPN raw-IP packets plus
        // root-captured Ethernet frames — unifies under LINKTYPE_ETHERNET: Ethernet frames
        // are written as-is and cooked/raw frames get a synthesized 14-byte Ethernet header
        // carrying their true ethertype. The old scheme stripped L2 headers and wrote
        // LINKTYPE_RAW for anything not 100% Ethernet, which silently corrupted every
        // non-IP frame (ARP, other ethertypes) — Wireshark then read frame bytes as IP.
        val allEthernet = packets.isNotEmpty() && packets.all { it.linkLayerType == LinkLayerType.ETHERNET }
        val allSll = packets.isNotEmpty() && packets.all { it.linkLayerType == LinkLayerType.LINUX_SLL }
        val allSll2 = packets.isNotEmpty() && packets.all { it.linkLayerType == LinkLayerType.LINUX_SLL2 }
        val linkType = when {
            allEthernet -> LINKTYPE_ETHERNET
            allSll -> LINKTYPE_LINUX_SLL
            allSll2 -> LINKTYPE_LINUX_SLL2
            packets.isEmpty() || packets.all { it.linkLayerType == LinkLayerType.RAW_TUN } -> LINKTYPE_RAW
            else -> LINKTYPE_ETHERNET
        }

        val buffered = BufferedOutputStream(outputStream, 16 * 1024)
        val globalHeader = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(PCAP_MAGIC_LE)
            putShort(2) // major version
            putShort(4) // minor version
            putInt(0) // thiszone (UTC)
            putInt(0) // sigfigs
            putInt(65535) // snaplen
            putInt(linkType)
        }.array()
        buffered.write(globalHeader)

        val pktHeaderBuf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        for (pkt in packets) {
            val payloadBytes = if (linkType == LINKTYPE_ETHERNET && pkt.linkLayerType != LinkLayerType.ETHERNET) {
                synthesizeEthernetFrame(pkt)
            } else {
                pkt.rawBytes
            }
            val sec = (pkt.timestampMs / 1000L).toInt()
            val usec = ((pkt.timestampMs % 1000L) * 1000L).toInt()
            pktHeaderBuf.clear()
            pktHeaderBuf.putInt(sec)
            pktHeaderBuf.putInt(usec)
            pktHeaderBuf.putInt(payloadBytes.size)
            pktHeaderBuf.putInt(payloadBytes.size)
            buffered.write(pktHeaderBuf.array())
            buffered.write(payloadBytes)
        }
        buffered.flush()
    }

    /**
     * Wraps a raw-IP or Linux-cooked frame in a synthesized Ethernet II header so it can be
     * stored in a LINKTYPE_ETHERNET file. The ethertype comes from the cooked header when
     * available (preserves ARP and other non-IP ethertypes exactly), else from the IP
     * version nibble. MAC addresses are zeroed: TUN/cooked captures never record them.
     */
    private fun synthesizeEthernetFrame(pkt: CapturedPacket): ByteArray {
        val raw = pkt.rawBytes
        val l3Offset = ipHeaderOffset(pkt.linkLayerType)
        if (raw.size <= l3Offset) return raw // truncated: write bytes as-is, don't invent
        val payload = raw.copyOfRange(l3Offset, raw.size)
        val etherType = when {
            pkt.linkLayerType == LinkLayerType.LINUX_SLL && raw.size >= 16 ->
                ((raw[14].toInt() and 0xFF) shl 8) or (raw[15].toInt() and 0xFF)
            pkt.linkLayerType == LinkLayerType.LINUX_SLL2 && raw.size >= 20 ->
                ((raw[0].toInt() and 0xFF) shl 8) or (raw[1].toInt() and 0xFF)
            payload.isNotEmpty() && (payload[0].toInt() ushr 4) == 6 -> 0x86DD
            else -> 0x0800
        }
        val frame = ByteArray(14 + payload.size)
        frame[12] = ((etherType ushr 8) and 0xFF).toByte()
        frame[13] = (etherType and 0xFF).toByte()
        System.arraycopy(payload, 0, frame, 14, payload.size)
        return frame
    }

    // Bounds for streaming import: no single record may exceed this (tcpdump's default
    // snaplen is 262144, so 4 MB is generous), and the whole import is capped so a huge
    // file can never be slurped into the heap (the old readBytes() path OOM'd here).
    private const val MAX_RECORD_BYTES = 4 * 1024 * 1024
    private const val MAX_IMPORT_BYTES = 256L * 1024 * 1024

    fun readPcap(inputStream: InputStream, maxPackets: Int = 5000): List<CapturedPacket> {
        val input = if (inputStream is BufferedInputStream) {
            inputStream
        } else {
            BufferedInputStream(inputStream, 64 * 1024)
        }

        val globalHeader = readFully(input, 24) ?: return emptyList()

        val magicLe = ByteBuffer.wrap(globalHeader, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val order = when (magicLe) {
            PCAP_MAGIC_LE -> ByteOrder.LITTLE_ENDIAN
            PCAP_MAGIC_BE -> ByteOrder.BIG_ENDIAN
            else -> throw IllegalArgumentException("Unsupported file format (not a standard .pcap file)")
        }

        val headerBuf = ByteBuffer.wrap(globalHeader).order(order)
        headerBuf.position(20)
        val linkType = headerBuf.int
        val dissectorLinkType = linkLayerForPcapType(linkType)

        var seqId = 1L
        var firstTimestampMs = 0L
        var totalBytes = 0L
        val packets = mutableListOf<CapturedPacket>()

        while (packets.size < maxPackets) {
            val recHeader = readFully(input, 16) ?: break // clean EOF or truncated header
            val recBuf = ByteBuffer.wrap(recHeader).order(order)
            val tsSec = recBuf.int.toLong() and 0xFFFFFFFFL
            val tsUsec = recBuf.int.toLong() and 0xFFFFFFFFL
            val inclLen = recBuf.int
            recBuf.int // origLen (unused)

            if (inclLen < 0 || inclLen > MAX_RECORD_BYTES) break // implausible record
            if (inclLen == 0) continue        // legal empty record; don't abort the import
            if (totalBytes + inclLen > MAX_IMPORT_BYTES) break     // byte budget reached
            val rawSlice = readFully(input, inclLen) ?: break      // truncated final record
            totalBytes += inclLen

            val tsMs = tsSec * 1000L + tsUsec / 1000L
            if (seqId == 1L) firstTimestampMs = tsMs

            val ipOffset = ipHeaderOffset(dissectorLinkType)
            val dir = inferImportDirection(rawSlice, ipOffset)

            packets.add(
                PacketDissector.dissect(
                    id = seqId++,
                    rawBytes = rawSlice,
                    timestampMs = tsMs,
                    relativeTimeMs = (tsMs - firstTimestampMs).coerceAtLeast(0L),
                    direction = dir,
                    linkLayerType = dissectorLinkType
                )
            )
        }
        return packets
    }

    /** Reads exactly [count] bytes, or returns null on EOF before that many bytes arrive. */
    private fun readFully(input: InputStream, count: Int): ByteArray? {
        val buf = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(buf, offset, count - offset)
            if (read < 0) return null
            offset += read
        }
        return buf
    }

    /**
     * Best-effort in/out inference for imported captures (pcap carries no direction).
     * The device is assumed to hold the private/local address: private-src IPv4 and
     * loopback/link-local/ULA-src IPv6 are outbound, public-src are inbound. The old
     * check was IPv4-only with a loose "first octet 10/172/192" test — every IPv6 packet
     * was labeled OUTBOUND (including responses), and public 172.x/192.x sources were
     * called outbound — corrupting in/out stats and direction filters on import.
     */
    private fun inferImportDirection(raw: ByteArray, ipOffset: Int): PacketDirection {
        if (raw.size < ipOffset + 1) return PacketDirection.OUTBOUND
        val version = (raw[ipOffset].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> {
                if (raw.size < ipOffset + 20) return PacketDirection.OUTBOUND
                val a = raw[ipOffset + 12].toInt() and 0xFF
                val b = raw[ipOffset + 13].toInt() and 0xFF
                val local = a == 10 ||
                    (a == 172 && b in 16..31) ||
                    (a == 192 && b == 168) ||
                    (a == 100 && b in 64..127) || // CGNAT (incl. carrier-grade ranges)
                    (a == 169 && b == 254) ||     // link-local
                    a == 127 || a == 0
                if (local) PacketDirection.OUTBOUND else PacketDirection.INBOUND
            }
            6 -> {
                if (raw.size < ipOffset + 40) return PacketDirection.OUTBOUND
                // IPv6 source address starts at byte 8 of the header (12 is the IPv4 layout).
                val b0 = raw[ipOffset + 8].toInt() and 0xFF
                val b1 = raw[ipOffset + 9].toInt() and 0xFF
                val local = (b0 == 0xFE && (b1 and 0xC0) == 0x80) || // fe80::/10 link-local
                    b0 == 0xFD || b0 == 0xFC ||                       // fc00::/7 ULA
                    b0 == 0                                           // :: / loopback-ish
                if (local) PacketDirection.OUTBOUND else PacketDirection.INBOUND
            }
            else -> PacketDirection.OUTBOUND // non-IP frame (ARP etc.): legacy default
        }
    }
}
