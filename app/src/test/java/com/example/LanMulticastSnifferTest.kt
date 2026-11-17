package com.example

import com.example.capture.LanMulticastSniffer
import com.example.dissector.DisplayFilterParser
import com.example.dissector.PacketDissector
import com.example.model.CaptureSource
import com.example.model.PacketDirection
import com.example.model.ProtocolType
import com.example.model.QuickFilter
import com.example.vpn.PacketChecksumUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.nio.charset.StandardCharsets

class LanMulticastSnifferTest {

    @Test
    fun buildLanUdpFrame_mdnsAnnouncementDissectsCleanly() {
        val mdnsPayload = byteArrayOf(
            0x00, 0x00, // tx id
            0x84.toByte(), 0x00, // standard response authoritative
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            6, 'p'.code.toByte(), 'i'.code.toByte(), 'r'.code.toByte(), 'a'.code.toByte(), 'i'.code.toByte(), 'b'.code.toByte(),
            5, 'l'.code.toByte(), 'o'.code.toByte(), 'c'.code.toByte(), 'a'.code.toByte(), 'l'.code.toByte(),
            0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x78,
            0x00, 0x04,
            192.toByte(), 168.toByte(), 1, 50
        )

        val frame = LanMulticastSniffer.buildLanUdpFrame(
            srcIp = InetAddress.getByName("192.168.1.50").address,
            dstIp = InetAddress.getByName(LanMulticastSniffer.MDNS_GROUP).address,
            srcPort = 5353,
            dstPort = 5353,
            payload = mdnsPayload
        )

        val storedCsum1 = ((frame[10].toInt() and 0xFF) shl 8) or (frame[11].toInt() and 0xFF)
        assertEquals(PacketChecksumUtils.computeIpv4Checksum(frame, 0, 20), storedCsum1)
        val lanPacket = PacketDissector.dissect(
            id = 1L,
            rawBytes = frame,
            timestampMs = 1_000L,
            relativeTimeMs = 0L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals(ProtocolType.DNS, lanPacket.protocol)
        assertEquals(CaptureSource.LAN_PROMISCUOUS, lanPacket.captureSource)
        assertEquals("192.168.1.50", lanPacket.srcIp)
        assertEquals("224.0.0.251", lanPacket.dstIp)
        assertEquals(5353, lanPacket.dstPort)
        assertTrue(lanPacket.streamKey.startsWith("LAN|"))

        val phonePacket = PacketDissector.dissect(
            id = 2L,
            rawBytes = frame,
            timestampMs = 1_000L,
            relativeTimeMs = 0L,
            direction = PacketDirection.OUTBOUND,
            captureSource = CaptureSource.DEVICE_VPN
        )
        assertEquals(CaptureSource.DEVICE_VPN, phonePacket.captureSource)
        assertTrue(phonePacket.streamKey.startsWith("PHONE|"))
        assertNotEquals(lanPacket.streamKey, phonePacket.streamKey)
    }

    @Test
    fun buildLanUdpFrame_ssdpNotifyDissectsPayload() {
        val ssdpText = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n"
        val frame = LanMulticastSniffer.buildLanUdpFrame(
            srcIp = InetAddress.getByName("192.168.1.1").address,
            dstIp = InetAddress.getByName(LanMulticastSniffer.SSDP_GROUP).address,
            srcPort = 54321,
            dstPort = 1900,
            payload = ssdpText.toByteArray(StandardCharsets.US_ASCII)
        )

        val storedCsum2 = ((frame[10].toInt() and 0xFF) shl 8) or (frame[11].toInt() and 0xFF)
        assertEquals(PacketChecksumUtils.computeIpv4Checksum(frame, 0, 20), storedCsum2)
        val packet = PacketDissector.dissect(
            id = 2L,
            rawBytes = frame,
            timestampMs = 2_000L,
            relativeTimeMs = 10L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        assertEquals("UDP", packet.transportProtocol)
        assertEquals(CaptureSource.LAN_PROMISCUOUS, packet.captureSource)
        assertEquals("192.168.1.1", packet.srcIp)
        assertEquals("239.255.255.250", packet.dstIp)
        assertEquals(1900, packet.dstPort)
        assertTrue(packet.payloadLength > 0)
    }

    @Test
    fun displayFilterParser_separatesLanAndPhoneSources() {
        val ssdpText = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n"
        val frame = LanMulticastSniffer.buildLanUdpFrame(
            srcIp = InetAddress.getByName("192.168.1.1").address,
            dstIp = InetAddress.getByName(LanMulticastSniffer.SSDP_GROUP).address,
            srcPort = 54321,
            dstPort = 1900,
            payload = ssdpText.toByteArray(StandardCharsets.US_ASCII)
        )
        val lanPacket = PacketDissector.dissect(
            id = 10L,
            rawBytes = frame,
            timestampMs = 2_000L,
            relativeTimeMs = 10L,
            direction = PacketDirection.INBOUND,
            captureSource = CaptureSource.LAN_PROMISCUOUS
        )
        val phonePacket = PacketDissector.dissect(
            id = 11L,
            rawBytes = frame,
            timestampMs = 2_005L,
            relativeTimeMs = 15L,
            direction = PacketDirection.OUTBOUND,
            captureSource = CaptureSource.DEVICE_VPN
        )

        val lanFilter = DisplayFilterParser.parse("lan", QuickFilter.ALL)
        assertTrue(lanFilter.isValid)
        assertTrue(lanFilter.matches(lanPacket))
        assertFalse(lanFilter.matches(phonePacket))

        val phoneFilter = DisplayFilterParser.parse("source == phone", QuickFilter.ALL)
        assertTrue(phoneFilter.isValid)
        assertFalse(phoneFilter.matches(lanPacket))
        assertTrue(phoneFilter.matches(phonePacket))

        val sourceEqLan = DisplayFilterParser.parse("source == lan", QuickFilter.ALL)
        assertTrue(sourceEqLan.isValid)
        assertTrue(sourceEqLan.matches(lanPacket))
        assertFalse(sourceEqLan.matches(phonePacket))
    }
}
