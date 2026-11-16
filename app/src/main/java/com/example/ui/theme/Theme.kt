package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.example.model.ProtocolType

private val DarkColorScheme = darkColorScheme(
    primary = TerracottaPrimary,
    onPrimary = Color(0xFF280B04),
    primaryContainer = Color(0xFF472219),
    onPrimaryContainer = Color(0xFFFFDAD0),
    secondary = DustyPinkAccent,
    onSecondary = Color(0xFF2A0914),
    secondaryContainer = Color(0xFF46222E),
    onSecondaryContainer = Color(0xFFFFD8E3),
    tertiary = WarmGoldLive,
    onTertiary = Color(0xFF261A02),
    tertiaryContainer = Color(0xFF443312),
    onTertiaryContainer = Color(0xFFFCE3A6),
    background = ConsoleBgDark,
    onBackground = ConsoleTextPrimaryDark,
    surface = ConsoleSurfaceDark,
    onSurface = ConsoleTextPrimaryDark,
    surfaceVariant = ConsoleSurfaceVariantDark,
    onSurfaceVariant = ConsoleTextSecondaryDark,
    surfaceContainerLowest = Color(0xFF050405),
    surfaceContainerLow = Color(0xFF0F0C0D),
    surfaceContainer = ConsoleSurfaceDark,
    surfaceContainerHigh = Color(0xFF1D1719),
    surfaceContainerHighest = Color(0xFF282023),
    outline = ConsoleOutlineDark,
    outlineVariant = Color(0xFF2B2124),
    error = RoseError,
    onError = Color(0xFF2D060D)
)

private val LightColorScheme = lightColorScheme(
    primary = TerracottaPrimaryDark,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFFDAD0),
    onPrimaryContainer = Color(0xFF3E1005),
    secondary = DustyPinkAccentDark,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFFFD8E3),
    onSecondaryContainer = Color(0xFF3D0C1C),
    tertiary = WarmGoldDark,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFCE7B2),
    onTertiaryContainer = Color(0xFF362200),
    background = ConsoleBgLight,
    onBackground = ConsoleTextPrimaryLight,
    surface = ConsoleSurfaceLight,
    onSurface = ConsoleTextPrimaryLight,
    surfaceVariant = ConsoleSurfaceVariantLight,
    onSurfaceVariant = ConsoleTextSecondaryLight,
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFFAF3F0),
    surfaceContainer = ConsoleSurfaceLight,
    surfaceContainerHigh = Color(0xFFF5E9E5),
    surfaceContainerHighest = Color(0xFFEADAD5),
    outline = ConsoleOutlineLight,
    outlineVariant = Color(0xFFEADAD5),
    error = Color(0xFFC43B4E),
    onError = Color.White
)

@Immutable
data class ProtocolColors(
    val tcp: Color,
    val tls: Color,
    val dns: Color,
    val http: Color,
    val udp: Color,
    val quic: Color,
    val icmp: Color,
    val other: Color,
    val outbound: Color,
    val inbound: Color,
    val hexHighlight: Color,
    val hexBg: Color
) {
    fun colorFor(protocol: ProtocolType): Color = when (protocol) {
        ProtocolType.TCP -> tcp
        ProtocolType.TLS -> tls
        ProtocolType.DNS -> dns
        ProtocolType.HTTP -> http
        ProtocolType.UDP -> udp
        ProtocolType.QUIC -> quic
        ProtocolType.ICMP -> icmp
        ProtocolType.OTHER -> other
    }
}

private val DarkProtocolColors = ProtocolColors(
    tcp = ProtoTcpColor,
    tls = ProtoTlsColor,
    dns = ProtoDnsColor,
    http = ProtoHttpColor,
    udp = ProtoUdpColor,
    quic = ProtoQuicColor,
    icmp = ProtoIcmpColor,
    other = ProtoOtherColor,
    outbound = OutboundAccent,
    inbound = InboundAccent,
    hexHighlight = Color(0xFF4E261C),
    hexBg = Color(0xFF070506)
)

private val LightProtocolColors = ProtocolColors(
    tcp = Color(0xFFC55336),
    tls = Color(0xFFB34E6B),
    dns = Color(0xFFB67E15),
    http = Color(0xFFB83E46),
    udp = Color(0xFFD26D2E),
    quic = Color(0xFFA54A75),
    icmp = Color(0xFFC93B52),
    other = Color(0xFF7B676B),
    outbound = Color(0xFFC55336),
    inbound = Color(0xFFB34E6B),
    hexHighlight = Color(0xFFFFD8CC),
    hexBg = Color(0xFFF7EFEA)
)

val LocalProtocolColors = staticCompositionLocalOf { DarkProtocolColors }

val WireTraceShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(18.dp),
    extraLarge = RoundedCornerShape(24.dp)
)

@Composable
fun WireTraceTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val protocolColors = if (darkTheme) DarkProtocolColors else LightProtocolColors

    CompositionLocalProvider(LocalProtocolColors provides protocolColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = WireTraceTypography,
            shapes = WireTraceShapes,
            content = content
        )
    }
}
