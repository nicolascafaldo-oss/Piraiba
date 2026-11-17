package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.model.ProbeType
import com.example.model.RootSandboxState
import com.example.model.RootSandboxStatus
import com.example.ui.theme.AmberAlert
import com.example.ui.theme.ConsoleBgDark
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive

@Composable
fun PromiscuousSandboxDialog(
    sandboxState: RootSandboxState,
    lanMulticastActive: Boolean,
    probeBusy: Boolean,
    onProbeRoot: () -> Unit,
    onSelectInterface: (String) -> Unit,
    onBpfFilterChange: (String) -> Unit,
    onTogglePromiscuousMode: (Boolean) -> Unit,
    onStartRootCapture: () -> Unit,
    onStopRootCapture: () -> Unit,
    onToggleLanMulticast: () -> Unit,
    onRunLanSweep: () -> Unit,
    onDismiss: () -> Unit
) {
    val isRunning = sandboxState.status == RootSandboxStatus.ROOT_RUNNING
    val isChecking = sandboxState.status == RootSandboxStatus.CHECKING
    val statusColor = when (sandboxState.status) {
        RootSandboxStatus.ROOT_RUNNING, RootSandboxStatus.ROOT_READY -> WarmGoldLive
        RootSandboxStatus.CHECKING -> MaterialTheme.colorScheme.secondary
        RootSandboxStatus.NO_ROOT_OR_DENIED, RootSandboxStatus.NO_TCPDUMP -> AmberAlert
        RootSandboxStatus.ERROR -> MaterialTheme.colorScheme.error
        RootSandboxStatus.UNCHECKED -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .heightIn(max = 680.dp)
                .testTag("promiscuous_sandbox_dialog")
        ) {
            Column(
                modifier = Modifier
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Terminal,
                            contentDescription = null,
                            tint = WarmGoldLive
                        )
                        Column {
                            Text(
                                text = "Promiscuous Sandbox",
                                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
                            )
                            Text(
                                text = "Root tcpdump pipe + LAN Multicast sandbox",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.testTag("close_sandbox_dialog_button")
                    ) {
                        Icon(Icons.Rounded.Close, contentDescription = "Close Promiscuous Sandbox")
                    }
                }

                // Privilege & Sandbox Kernel Boundary Card
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerLow,
                    border = BorderStroke(1.dp, statusColor.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(8.dp)
                                        .clip(CircleShape)
                                        .background(statusColor)
                                )
                                Text(
                                    text = sandboxState.status.label,
                                    style = MaterialTheme.typography.labelLarge.copy(
                                        fontFamily = MonoFontFamily,
                                        fontWeight = FontWeight.Bold
                                    ),
                                    color = statusColor
                                )
                            }
                            if (isRunning) {
                                Text(
                                    text = "${sandboxState.capturedFrames} root frames",
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = WarmGoldLive
                                )
                            }
                        }

                        Text(
                            text = sandboxState.statusDetail,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )

                        if (sandboxState.status == RootSandboxStatus.NO_ROOT_OR_DENIED ||
                            sandboxState.status == RootSandboxStatus.UNCHECKED
                        ) {
                            Row(
                                verticalAlignment = Alignment.Top,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.Security,
                                    contentDescription = null,
                                    tint = AmberAlert,
                                    modifier = Modifier
                                        .padding(top = 2.dp)
                                        .size(15.dp)
                                )
                                Text(
                                    text = "Wireshark-style wlan0 hardware promiscuous sniffing requires Linux UID 0 / CAP_NET_RAW (rooted su + tcpdump). Stock unrooted Android enforces app sandboxing at the kernel level, so unrooted devices can inspect all phone traffic (tun0) plus LAN mDNS/SSDP/LLMNR/WSD broadcasts.",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                // Interface Selection
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Capture Interface",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        sandboxState.availableInterfaces.forEach { iface ->
                            val selected = sandboxState.selectedInterface == iface
                            FilterChip(
                                selected = selected,
                                enabled = !isRunning,
                                onClick = { onSelectInterface(iface) },
                                label = {
                                    Text(
                                        text = iface,
                                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = MonoFontFamily)
                                    )
                                },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = WarmGoldLive.copy(alpha = 0.2f),
                                    selectedLabelColor = WarmGoldLive
                                )
                            )
                        }
                    }
                }

                // IFF_PROMISC + BPF Filter
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Hardware Promiscuous Flag (IFF_PROMISC)",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Text(
                            text = "Pass without -p flag to capture all Wi-Fi NIC frames",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = sandboxState.promiscuousMode,
                        enabled = !isRunning,
                        onCheckedChange = onTogglePromiscuousMode,
                        modifier = Modifier.testTag("root_promiscuous_switch")
                    )
                }

                OutlinedTextField(
                    value = sandboxState.bpfFilter,
                    onValueChange = onBpfFilterChange,
                    enabled = !isRunning,
                    singleLine = true,
                    label = { Text("tcpdump BPF Filter (optional)") },
                    placeholder = { Text("e.g. not port 5555 and (arp or udp or tcp)") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("root_bpf_input")
                )

                // Root Sandbox Action Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = onProbeRoot,
                        enabled = !isRunning && !isChecking,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("probe_root_sandbox_button")
                    ) {
                        Icon(Icons.Rounded.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(if (isChecking) "Probing..." else "Probe Root", maxLines = 1)
                    }

                    Button(
                        onClick = if (isRunning) onStopRootCapture else onStartRootCapture,
                        enabled = isRunning || (sandboxState.suAvailable && sandboxState.tcpdumpPath != null),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isRunning) MaterialTheme.colorScheme.error else WarmGoldLive,
                            contentColor = if (isRunning) MaterialTheme.colorScheme.onError else ConsoleBgDark
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("start_stop_root_sandbox_button")
                    ) {
                        Icon(
                            imageVector = if (isRunning) Icons.Rounded.Stop else Icons.Rounded.PlayArrow,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(if (isRunning) "Stop Root" else "Start Root", maxLines = 1)
                    }
                }

                // Non-root LAN Multicast Quick Actions
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerLow,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Non-Root LAN Multicast Sandbox",
                                    style = MaterialTheme.typography.labelLarge
                                )
                                Text(
                                    text = "Listens on mDNS (5353), SSDP (1900), LLMNR (5355) & WSD (3702)",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Switch(
                                checked = lanMulticastActive,
                                onCheckedChange = { onToggleLanMulticast() }
                            )
                        }
                        OutlinedButton(
                            onClick = onRunLanSweep,
                            enabled = !probeBusy,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 42.dp)
                                .testTag("sandbox_lan_sweep_button")
                        ) {
                            Icon(Icons.Rounded.WifiTethering, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(ProbeType.LAN_DISCOVERY.label)
                        }
                    }
                }

                // Sandbox Console Output
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "Sandbox Console Log",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = ConsoleBgDark,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 90.dp, max = 160.dp)
                    ) {
                        Column(
                            modifier = Modifier
                                .padding(10.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(3.dp)
                        ) {
                            val logs = if (sandboxState.consoleLogs.isEmpty()) {
                                listOf("[sandbox] Ready. Tap Probe Root to check su/tcpdump on this device.")
                            } else {
                                sandboxState.consoleLogs
                            }
                            logs.forEach { line ->
                                Text(
                                    text = line,
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.9f)
                                )
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text("Close")
                    }
                }
            }
        }
    }
}
