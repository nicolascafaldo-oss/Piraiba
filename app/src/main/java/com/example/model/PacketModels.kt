package com.example.model

enum class ProtocolType(val label: String) {
    TCP("TCP"),
    TLS("TLS"),
    HTTP("HTTP"),
    DNS("DNS"),
    UDP("UDP"),
    QUIC("QUIC"),
    ICMP("ICMP"),
    OTHER("IP")
}

enum class PacketDirection(val shortLabel: String) {
    OUTBOUND("OUT"),
    INBOUND("IN")
}

enum class LinkLayerType {
    RAW_TUN,
    ETHERNET
}

data class ProtocolField(
    val label: String,
    val value: String,
    val byteStart: Int,
    val byteEnd: Int
)

data class ProtocolLayer(
    val name: String,
    val byteStart: Int,
    val byteEnd: Int,
    val fields: List<ProtocolField>
)

data class DnsMapping(
    val ip: String,
    val domain: String
)

enum class ResolutionSource(val shortLabel: String, val priority: Int) {
    REVERSE_PTR("PTR", 1),
    HTTP_HOST("HTTP", 2),
    TLS_SNI("SNI", 3),
    DNS_ANSWER("DNS", 4)
}

data class ResolvedHost(
    val ip: String,
    val domain: String,
    val source: ResolutionSource,
    val updatedAtMs: Long
)

data class CapturedPacket(
    val id: Long,
    val timestampMs: Long,
    val relativeTimeMs: Long,
    val direction: PacketDirection,
    val ipVersion: Int,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val transportProtocol: String,
    val protocol: ProtocolType,
    val length: Int,
    val hostOrSni: String?,
    val infoSummary: String,
    val tcpFlags: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val rawBytes: ByteArray,
    val layers: List<ProtocolLayer>,
    val linkLayerType: LinkLayerType = LinkLayerType.RAW_TUN,
    val dnsMappings: List<DnsMapping> = emptyList()
) {
    val streamKey: String
        get() {
            val a = "$srcIp:$srcPort"
            val b = "$dstIp:$dstPort"
            return if (a <= b) "$transportProtocol|$a|$b" else "$transportProtocol|$b|$a"
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CapturedPacket) return false
        return id == other.id && timestampMs == other.timestampMs && length == other.length
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + timestampMs.hashCode()
        result = 31 * result + length
        return result
    }
}

data class ConversationStream(
    val key: String,
    val localEndpoint: String,
    val remoteEndpoint: String,
    val remoteIp: String,
    val remotePort: Int,
    val protocol: ProtocolType,
    val transportProtocol: String,
    val hostLabel: String?,
    val packetCount: Int,
    val bytesOut: Long,
    val bytesIn: Long,
    val firstSeenMs: Long,
    val lastSeenMs: Long
) {
    val totalBytes: Long get() = bytesOut + bytesIn
}

data class ThroughputPoint(
    val bucketSecond: Long,
    val packetsPerSec: Int,
    val bytesOut: Long,
    val bytesIn: Long
)

data class ProtocolStat(
    val protocol: ProtocolType,
    val packetCount: Int,
    val totalBytes: Long,
    val fraction: Float
)

enum class QuickFilter(val label: String) {
    ALL("All"),
    TCP("TCP"),
    TLS("TLS"),
    DNS("DNS"),
    HTTP("HTTP"),
    UDP("UDP"),
    ICMP("ICMP")
}

enum class ProbeType(val label: String, val description: String) {
    DNS_QUERY("DNS Lookup", "Send live UDP/53 DNS A-query to 8.8.8.8"),
    HTTP_GET("HTTP Request", "Send live TCP/80 GET request to example.com"),
    HTTPS_TLS("TLS Handshake", "Perform live TCP/443 TLS 1.3 handshake with SNI")
}
