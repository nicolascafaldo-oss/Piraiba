package com.example

import com.example.dissector.PacketDissector
import com.example.dissector.PcapCodec
import com.example.model.LinkLayerType
import com.example.model.PacketDirection
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Pins the export/import integrity rules of [PcapCodec]:
 *  - homogeneous captures keep their native link type (SLL frames are NOT stripped),
 *  - mixed captures unify under LINKTYPE_ETHERNET with synthesized headers for raw/cooked
 *    packets while real Ethernet frames (e.g. ARP) pass through byte-identically,
 *  - import infers direction per address family (IPv6 used to always become OUTBOUND),
 *  - a zero-length record does not abort the rest of an import.
 */
class PcapCodecIntegrityTest {

    @Test
    fun mixedCaptureExportsAsEthernetAndPreservesArpFrames() {
        val arpFrame = buildArpRequestFrame()
        val arpPkt = PacketDissector.dissect(
            1L, arpFrame, 1_700_000_000_000L, 0L, PacketDirection.INBOUND, LinkLayerType.ETHERNET
        )
        assertTrue(arpPkt.transportProtocol == "ARP")

        val ipRaw = buildIpv4UdpRaw(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 53123,
            dstPort = 53
        )
        val ipPkt = PacketDissector.dissect(
            2L, ipRaw, 1_700_000_000_001L, 1L, PacketDirection.OUTBOUND, LinkLayerType.RAW_TUN
        )

        val out = ByteArrayOutputStream()
        PcapCodec.writePcap(listOf(arpPkt, ipPkt), out)
        val bytes = out.toByteArray()
        assertEquals(PcapCodec.LINKTYPE_ETHERNET, littleEndianInt(bytes, 20))

        val reimported = PcapCodec.readPcap(ByteArrayInputStream(bytes))
        assertEquals(2, reimported.size)

        // ARP frame must round-trip byte-identically (the old strip-to-RAW export
        // destroyed it by reinterpreting ARP bytes as IP).
        val arp2 = reimported[0]
        assertEquals(LinkLayerType.ETHERNET, arp2.linkLayerType)
        assertEquals("ARP", arp2.transportProtocol)
        assertArrayEquals(arpFrame, arp2.rawBytes)

        // Raw IP packet gets a synthesized Ethernet header: zeroed MACs, ethertype 0x0800,
        // original IP bytes untouched behind it.
        val ip2 = reimported[1]
        assertEquals(LinkLayerType.ETHERNET, ip2.linkLayerType)
        assertEquals("10.1.10.1", ip2.srcIp)
        assertEquals("8.8.8.8", ip2.dstIp)
        assertEquals(53, ip2.dstPort)
        val frame = ip2.rawBytes
        assertEquals(14 + ipRaw.size, frame.size)
        assertTrue(frame.copyOf(12).all { it == 0.toByte() })
        assertEquals(0x08, frame[12].toInt() and 0xFF)
        assertEquals(0x00, frame[13].toInt() and 0xFF)
        assertArrayEquals(ipRaw, frame.copyOfRange(14, frame.size))
        assertEquals(PacketDirection.OUTBOUND, ip2.direction) // private src side
    }

    @Test
    fun homogeneousLinuxSllExportKeepsNativeLinkType() {
        val sllHeader = ByteArray(16).apply {
            this[14] = 0x08 // ethertype IPv4
            this[15] = 0x00
        }
        val udpIp = buildIpv4UdpRaw(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 90),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 44444,
            dstPort = 5353
        )
        val frame = sllHeader + udpIp
        val pkt = PacketDissector.dissect(
            1L, frame, 1_700_000_000_000L, 0L, PacketDirection.INBOUND, LinkLayerType.LINUX_SLL
        )

        val out = ByteArrayOutputStream()
        PcapCodec.writePcap(listOf(pkt), out)
        val bytes = out.toByteArray()
        assertEquals(PcapCodec.LINKTYPE_LINUX_SLL, littleEndianInt(bytes, 20))

        val reimported = PcapCodec.readPcap(ByteArrayInputStream(bytes))
        assertEquals(1, reimported.size)
        assertEquals(LinkLayerType.LINUX_SLL, reimported[0].linkLayerType)
        assertArrayEquals(frame, reimported[0].rawBytes)
        assertEquals(5353, reimported[0].dstPort)
    }

    @Test
    fun importInfersDirectionPerAddressFamily() {
        val v6Global = buildIpv6UdpRaw(
            src = byteArrayOf(
                0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ),
            dst = byteArrayOf(
                0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
            )
        )
        val v6Ula = buildIpv6UdpRaw(
            src = byteArrayOf(
                0xfd.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ),
            dst = byteArrayOf(
                0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
            )
        )
        val v4Public = buildIpv4UdpRaw(
            srcIp = byteArrayOf(8, 8, 8, 8),
            dstIp = byteArrayOf(10, 1, 10, 1),
            srcPort = 53,
            dstPort = 53123
        )
        val v4Private = buildIpv4UdpRaw(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 53123,
            dstPort = 443
        )

        val file = buildRawLinktypePcap(listOf(v6Global, v6Ula, v4Public, v4Private))
        val imported = PcapCodec.readPcap(ByteArrayInputStream(file))
        assertEquals(4, imported.size)
        assertEquals(PacketDirection.INBOUND, imported[0].direction)  // public IPv6 src
        assertEquals(PacketDirection.OUTBOUND, imported[1].direction) // ULA IPv6 src
        assertEquals(PacketDirection.INBOUND, imported[2].direction)  // public IPv4 src
        assertEquals(PacketDirection.OUTBOUND, imported[3].direction) // RFC1918 src
    }

    @Test
    fun zeroLengthRecordDoesNotAbortImport() {
        val valid = buildIpv4UdpRaw(
            srcIp = byteArrayOf(10, 1, 10, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 12345,
            dstPort = 80
        )
        val file = ByteArrayOutputStream().apply {
            writeRawPcapGlobalHeader(PcapCodec.LINKTYPE_RAW)
            writeRawPcapRecord(0, 0, ByteArray(0)) // legal empty record
            writeRawPcapRecord(1_700_000_000, 0, valid)
        }.toByteArray()

        val imported = PcapCodec.readPcap(ByteArrayInputStream(file))
        assertEquals(1, imported.size)
        assertEquals(80, imported[0].dstPort)
    }

    // --- helpers ---

    private fun littleEndianInt(buf: ByteArray, offset: Int): Int =
        (buf[offset].toInt() and 0xFF) or
            ((buf[offset + 1].toInt() and 0xFF) shl 8) or
            ((buf[offset + 2].toInt() and 0xFF) shl 16) or
            ((buf[offset + 3].toInt() and 0xFF) shl 24)

    private fun buildRawLinktypePcap(records: List<ByteArray>): ByteArray =
        ByteArrayOutputStream().apply {
            writeRawPcapGlobalHeader(PcapCodec.LINKTYPE_RAW)
            records.forEachIndexed { i, rec -> writeRawPcapRecord(1_700_000_000L + i, i * 1000L, rec) }
        }.toByteArray()

    private fun ByteArrayOutputStream.writeRawPcapGlobalHeader(linkType: Int) {
        write(byteArrayOf(0xd4.toByte(), 0xc3.toByte(), 0xb2.toByte(), 0xa1.toByte()))
        writeShortLe(2)
        writeShortLe(4)
        writeIntLe(0)
        writeIntLe(0)
        writeIntLe(65535)
        writeIntLe(linkType)
    }

    private fun ByteArrayOutputStream.writeRawPcapRecord(sec: Long, usec: Long, rec: ByteArray) {
        writeIntLe(sec.toInt())
        writeIntLe(usec.toInt())
        writeIntLe(rec.size)
        writeIntLe(rec.size)
        write(rec)
    }

    private fun ByteArrayOutputStream.writeShortLe(v: Int) {
        write(v and 0xFF)
        write((v ushr 8) and 0xFF)
    }

    private fun ByteArrayOutputStream.writeIntLe(v: Int) {
        write(v and 0xFF)
        write((v ushr 8) and 0xFF)
        write((v ushr 16) and 0xFF)
        write((v ushr 24) and 0xFF)
    }

    private fun buildIpv4UdpRaw(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int): ByteArray {
        val payload = ByteArray(4)
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 17 // UDP
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[20] = ((srcPort ushr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        return pkt
    }

    private fun buildIpv6UdpRaw(src: ByteArray, dst: ByteArray): ByteArray {
        val pkt = ByteArray(48)
        pkt[0] = 0x60
        pkt[4] = 0x00
        pkt[5] = 8 // UDP payload length
        pkt[6] = 17 // next header = UDP
        pkt[7] = 64 // hop limit
        System.arraycopy(src, 0, pkt, 8, 16)
        System.arraycopy(dst, 0, pkt, 24, 16)
        pkt[40] = 0x30
        pkt[41] = 0x39 // src port 12345
        pkt[42] = 0x01
        pkt[43] = 0xBB.toByte() // dst port 443
        pkt[44] = 0x00
        pkt[45] = 8 // udp length
        return pkt
    }

    private fun buildArpRequestFrame(): ByteArray {
        val frame = ByteArray(42)
        // Ethernet: dst broadcast, src 00:11:22:33:44:55, ethertype ARP
        frame[0] = 0xFF.toByte(); frame[1] = 0xFF.toByte(); frame[2] = 0xFF.toByte()
        frame[3] = 0xFF.toByte(); frame[4] = 0xFF.toByte(); frame[5] = 0xFF.toByte()
        frame[6] = 0x00; frame[7] = 0x11; frame[8] = 0x22
        frame[9] = 0x33; frame[10] = 0x44; frame[11] = 0x55
        frame[12] = 0x08; frame[13] = 0x06
        // ARP: ethernet/IPv4 request who-has 192.168.1.1 tell 192.168.1.25
        frame[14] = 0x00; frame[15] = 0x01 // htype ethernet
        frame[16] = 0x08; frame[17] = 0x00 // ptype IPv4
        frame[18] = 6 // hlen
        frame[19] = 4 // plen
        frame[20] = 0x00; frame[21] = 0x01 // op request
        frame[22] = 0xAA.toByte(); frame[23] = 0xBB.toByte(); frame[24] = 0xCC.toByte()
        frame[25] = 0xDD.toByte(); frame[26] = 0xEE.toByte(); frame[27] = 0xFF.toByte()
        frame[28] = 192.toByte(); frame[29] = 168.toByte(); frame[30] = 1; frame[31] = 25
        // target MAC bytes 32..37 stay zero (unresolved)
        frame[38] = 192.toByte(); frame[39] = 168.toByte(); frame[40] = 1; frame[41] = 1
        return frame
    }
}
