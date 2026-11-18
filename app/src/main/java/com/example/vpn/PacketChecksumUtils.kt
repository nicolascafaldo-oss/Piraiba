package com.example.vpn

/**
 * Computes RFC 1071 internet checksums for IPv4 headers and TCP/UDP pseudo-headers
 * so packets written back to the Android TUN interface are accepted by the kernel stack.
 */
object PacketChecksumUtils {

    fun computeIpv4Checksum(packet: ByteArray, offset: Int = 0, ihl: Int): Int {
        // Bounds guard: callers live on the capture/selector threads where an
        // ArrayIndexOutOfBoundsException would kill packet processing. A short buffer is a
        // caller bug; return 0 (an invalid checksum — the packet gets dropped downstream)
        // instead of throwing.
        if (offset < 0 || ihl < 20 || offset + ihl > packet.size) return 0
        var sum = 0L
        var i = offset
        val end = offset + ihl
        while (i + 1 < end) {
            if (i != offset + 10) { // skip checksum field itself
                val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
                sum += word
            }
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    fun updateIpv4Checksum(packet: ByteArray, offset: Int = 0, ihl: Int) {
        // Mirror compute()'s bounds guard: compute returns 0 on a short buffer, but writing
        // the field at offset+10/11 would still throw — and callers run on capture threads.
        if (offset < 0 || ihl < 20 || offset + 11 >= packet.size) return
        val csum = computeIpv4Checksum(packet, offset, ihl)
        packet[offset + 10] = ((csum ushr 8) and 0xFF).toByte()
        packet[offset + 11] = (csum and 0xFF).toByte()
    }

    fun updateTransportChecksum(
        packet: ByteArray,
        ipOffset: Int,
        ihl: Int,
        protocol: Int,
        transportLen: Int
    ) {
        // Pseudo-header reads below touch ipOffset+12..ipOffset+17 — guard them.
        if (ipOffset < 0 || ipOffset + 20 > packet.size) return
        val l4Offset = ipOffset + ihl
        val checksumFieldOffset = when (protocol) {
            6 -> l4Offset + 16 // TCP checksum
            17 -> l4Offset + 6 // UDP checksum
            else -> return
        }
        if (checksumFieldOffset + 1 >= packet.size) return

        // Zero existing checksum
        packet[checksumFieldOffset] = 0
        packet[checksumFieldOffset + 1] = 0

        var sum = 0L
        // Pseudo-header: src IP (4 bytes), dst IP (4 bytes)
        for (i in 0 until 4 step 2) {
            sum += ((packet[ipOffset + 12 + i].toInt() and 0xFF) shl 8) or
                (packet[ipOffset + 13 + i].toInt() and 0xFF)
            sum += ((packet[ipOffset + 16 + i].toInt() and 0xFF) shl 8) or
                (packet[ipOffset + 17 + i].toInt() and 0xFF)
        }
        sum += (protocol and 0xFF).toLong()
        sum += (transportLen and 0xFFFF).toLong()

        // Transport header + payload
        var idx = l4Offset
        val end = minOf(l4Offset + transportLen, packet.size)
        while (idx + 1 < end) {
            sum += ((packet[idx].toInt() and 0xFF) shl 8) or (packet[idx + 1].toInt() and 0xFF)
            idx += 2
        }
        if (idx < end) {
            sum += (packet[idx].toInt() and 0xFF) shl 8
        }

        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        var finalChecksum = (sum.inv() and 0xFFFF).toInt()
        if (protocol == 17 && finalChecksum == 0) {
            finalChecksum = 0xFFFF
        }
        packet[checksumFieldOffset] = ((finalChecksum ushr 8) and 0xFF).toByte()
        packet[checksumFieldOffset + 1] = (finalChecksum and 0xFF).toByte()
    }
}
