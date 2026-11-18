package com.example

import com.example.vpn.PacketChecksumUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Known-answer and self-consistency tests for the RFC 1071 checksum code the VPN
 * forwarder depends on. Checksums were previously only *called* from packet-building
 * helpers but never asserted — a silent regression here breaks live connectivity
 * without failing any test.
 */
class PacketChecksumUtilsTest {

    // Classic RFC 1071 example header (expected checksum 0xb861), checksum field zeroed.
    private fun rfcExampleHeader(): ByteArray = byteArrayOf(
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0.toByte(), 0xA8.toByte(), 0x00, 0x01,
        0xC0.toByte(), 0xA8.toByte(), 0x00, 0xC7.toByte()
    )

    @Test
    fun ipv4HeaderChecksumMatchesKnownVector() {
        assertEquals(0xB861, PacketChecksumUtils.computeIpv4Checksum(rfcExampleHeader(), 0, 20))
    }

    @Test
    fun updateIpv4ChecksumWritesFieldThatValidatesToZero() {
        val pkt = rfcExampleHeader()
        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        assertEquals(0xB8, pkt[10].toInt() and 0xFF)
        assertEquals(0x61, pkt[11].toInt() and 0xFF)
        // Re-summing the full header INCLUDING the checksum field must fold to a
        // complement of 0 for a valid packet.
        assertEquals(0, onesComplementFold(sumWords(pkt, 0, 20)))
    }

    @Test
    fun tcpChecksumWithPseudoHeaderValidatesToZero() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val pkt = buildIpv4Tcp(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(93, 184.toByte(), 215.toByte(), 14),
            payload = payload
        )
        val tcpLen = 20 + payload.size
        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 6, tcpLen)

        // Independent verification: pseudo-header (src, dst, protocol, length) plus the
        // TCP segment INCLUDING its checksum must fold to a complement of 0.
        var sum = 0L
        sum += sumWords(pkt, 12, 8)     // src IP + dst IP
        sum += 6L                        // protocol TCP
        sum += tcpLen.toLong()
        sum += sumWords(pkt, 20, tcpLen) // TCP header + payload incl. checksum
        assertEquals(0, onesComplementFold(sum))
    }

    @Test
    fun udpChecksumWithPseudoHeaderValidatesToZero() {
        val payload = ByteArray(7) { it.toByte() } // odd length exercises tail handling
        val pkt = buildIpv4Udp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 50),
            dstIp = byteArrayOf(8, 8, 8, 8),
            payload = payload
        )
        val udpLen = 8 + payload.size
        PacketChecksumUtils.updateIpv4Checksum(pkt, 0, 20)
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 17, udpLen)

        var sum = 0L
        sum += sumWords(pkt, 12, 8)
        sum += 17L
        sum += udpLen.toLong()
        sum += sumWords(pkt, 20, udpLen)
        assertEquals(0, onesComplementFold(sum))
    }

    @Test
    fun boundsGuardsNeverThrowOnCaptureThreads() {
        // Short / inverted buffers: compute returns 0, writers return without throwing.
        assertEquals(0, PacketChecksumUtils.computeIpv4Checksum(ByteArray(10), 0, 20))
        assertEquals(0, PacketChecksumUtils.computeIpv4Checksum(ByteArray(40), -1, 20))
        PacketChecksumUtils.updateIpv4Checksum(ByteArray(10), 0, 20)
        PacketChecksumUtils.updateIpv4Checksum(ByteArray(12), 0, 20) // exactly at field
        PacketChecksumUtils.updateTransportChecksum(ByteArray(10), 0, 20, 6, 20)
        PacketChecksumUtils.updateTransportChecksum(ByteArray(40), -1, 20, 6, 20)

        // Unsupported protocol must leave the buffer untouched.
        val pkt = ByteArray(64)
        val before = pkt.copyOf()
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 1 /* ICMP */, 20)
        assertTrue(pkt.contentEquals(before))

        // Transport length claiming far more than the buffer holds must not throw.
        PacketChecksumUtils.updateTransportChecksum(pkt, 0, 20, 6, 5000)
    }

    // --- helpers ---

    private fun sumWords(buf: ByteArray, offset: Int, len: Int): Long {
        var sum = 0L
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xFF) shl 8
        return sum
    }

    private fun onesComplementFold(sum: Long): Int {
        var s = sum
        while ((s ushr 16) != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    private fun buildIpv4Header(srcIp: ByteArray, dstIp: ByteArray, proto: Int, l4Len: Int): ByteArray {
        val totalLen = 20 + l4Len
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64 // TTL
        pkt[9] = proto.toByte()
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        return pkt
    }

    private fun buildIpv4Tcp(srcIp: ByteArray, dstIp: ByteArray, payload: ByteArray): ByteArray {
        val pkt = buildIpv4Header(srcIp, dstIp, 6, 20 + payload.size)
        // src port 12345, dst port 80
        pkt[20] = 0x30
        pkt[21] = 0x39
        pkt[22] = 0
        pkt[23] = 80
        pkt[32] = 0x50 // data offset 5 words
        pkt[33] = 0x18 // PSH + ACK
        pkt[34] = 0x10
        pkt[35] = 0x00 // window
        System.arraycopy(payload, 0, pkt, 40, payload.size)
        return pkt
    }

    private fun buildIpv4Udp(srcIp: ByteArray, dstIp: ByteArray, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val pkt = buildIpv4Header(srcIp, dstIp, 17, udpLen)
        pkt[20] = 0x30
        pkt[21] = 0x39 // src port 12345
        pkt[22] = 0x01
        pkt[23] = 0xBB.toByte() // dst port 443
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        return pkt
    }
}
