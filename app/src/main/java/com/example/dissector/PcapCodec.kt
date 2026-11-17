package com.example.dissector

import com.example.model.CapturedPacket
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Standard libpcap (.pcap) binary encoder & decoder supporting LINKTYPE_RAW (101),
 * LINKTYPE_ETHERNET (1), LINKTYPE_LINUX_SLL (113), and LINKTYPE_LINUX_SLL2 (276).
 * Exported files open natively in desktop Wireshark, tcpdump, and tshark.
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
        val allEthernet = packets.isNotEmpty() && packets.all { it.linkLayerType == LinkLayerType.ETHERNET }
        val linkType = if (allEthernet) LINKTYPE_ETHERNET else LINKTYPE_RAW

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
            val stripLen = ipHeaderOffset(pkt.linkLayerType)
            val payloadBytes = if (linkType == LINKTYPE_RAW && stripLen > 0 && pkt.rawBytes.size > stripLen) {
                pkt.rawBytes.copyOfRange(stripLen, pkt.rawBytes.size)
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

    fun readPcap(inputStream: InputStream, maxPackets: Int = 5000): List<CapturedPacket> {
        val allBytes = inputStream.readBytes()
        if (allBytes.size < 24) return emptyList()

        val magicLe = ByteBuffer.wrap(allBytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val order = when (magicLe) {
            PCAP_MAGIC_LE -> ByteOrder.LITTLE_ENDIAN
            PCAP_MAGIC_BE -> ByteOrder.BIG_ENDIAN
            else -> throw IllegalArgumentException("Unsupported file format (not a standard .pcap file)")
        }

        val headerBuf = ByteBuffer.wrap(allBytes, 0, 24).order(order)
        headerBuf.position(20)
        val linkType = headerBuf.int
        val dissectorLinkType = linkLayerForPcapType(linkType)

        var cursor = 24
        var seqId = 1L
        var firstTimestampMs = 0L
        val packets = mutableListOf<CapturedPacket>()

        while (cursor + 16 <= allBytes.size && packets.size < maxPackets) {
            val recBuf = ByteBuffer.wrap(allBytes, cursor, 16).order(order)
            val tsSec = recBuf.int.toLong() and 0xFFFFFFFFL
            val tsUsec = recBuf.int.toLong() and 0xFFFFFFFFL
            val inclLen = recBuf.int
            recBuf.int
            cursor += 16

            if (inclLen <= 0 || inclLen > 65535 || cursor + inclLen > allBytes.size) break

            val rawSlice = allBytes.copyOfRange(cursor, cursor + inclLen)
            cursor += inclLen

            val tsMs = tsSec * 1000L + tsUsec / 1000L
            if (seqId == 1L) firstTimestampMs = tsMs

            val ipOffset = ipHeaderOffset(dissectorLinkType)
            val dir = if (rawSlice.size >= ipOffset + 20 && (rawSlice[ipOffset].toInt() ushr 4) == 4) {
                val srcFirst = rawSlice[ipOffset + 12].toInt() and 0xFF
                if (srcFirst == 10 || srcFirst == 192 || srcFirst == 172) PacketDirection.OUTBOUND else PacketDirection.INBOUND
            } else {
                PacketDirection.OUTBOUND
            }

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
}
