package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.HelpOutline
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Clear
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.VerticalAlignBottom
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.model.CapturedPacket
import com.example.model.ProbeType
import com.example.model.QuickFilter
import com.example.model.ResolvedHost
import com.example.ui.components.DirectionPill
import com.example.ui.components.FilterHelpDialog
import com.example.ui.components.MiniThroughputSparkline
import com.example.ui.components.ProtocolBadge
import com.example.ui.components.formatByteCount
import com.example.ui.theme.AmberAlert
import com.example.ui.theme.ConsoleBgDark
import com.example.ui.theme.LocalProtocolColors
import com.example.ui.theme.MonoFontFamily
import com.example.ui.theme.WarmGoldLive
import com.example.viewmodel.CaptureUiState

@Composable
fun CaptureScreen(
    uiState: CaptureUiState,
    probeBusy: Boolean,
    onStartCapture: () -> Unit,
    onOpenPcap: () -> Unit,
    onRunProbe: (ProbeType) -> Unit,
    onFilterQueryChange: (String) -> Unit,
    onQuickFilterSelected: (QuickFilter) -> Unit,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit,
    onSelectPacket: (CapturedPacket) -> Unit,
    modifier: Modifier = Modifier
) {
    var showFilterHelp by remember { mutableStateOf(false) }
    var showFilterBuilder by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val focusManager = LocalFocusManager.current

    LaunchedEffect(uiState.packets.size, uiState.autoScroll) {
        if (uiState.autoScroll && uiState.packets.isNotEmpty()) {
            listState.scrollToItem(uiState.packets.lastIndex)
        }
    }

    if (showFilterHelp) {
        FilterHelpDialog(
            onSelectExample = { onFilterQueryChange(it) },
            onDismiss = { showFilterHelp = false }
        )
    }

    if (showFilterBuilder) {
        CriteriaFilterDialog(
            currentQuickFilter = uiState.quickFilter,
            onApply = { expr, quick ->
                onQuickFilterSelected(quick)
                onFilterQueryChange(expr)
                showFilterBuilder = false
            },
            onDismiss = { showFilterBuilder = false }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp)
    ) {
        TelemetrySummaryStrip(
            uiState = uiState,
            onToggleAutoScroll = onToggleAutoScroll,
            onToggleResolveHostnames = onToggleResolveHostnames
        )

        Spacer(modifier = Modifier.height(8.dp))

        val hasQuery = uiState.filterQuery.isNotBlank()
        val isFilterValid = uiState.filterValidation.isValid
        val borderColor = when {
            !hasQuery -> MaterialTheme.colorScheme.outlineVariant
            isFilterValid -> WarmGoldLive
            else -> AmberAlert
        }

        OutlinedTextField(
            value = uiState.filterQuery,
            onValueChange = onFilterQueryChange,
            singleLine = true,
            placeholder = {
                Text(
                    text = "Search payload, host, or filter (ip.src == ..., port == 443)",
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            },
            leadingIcon = {
                Icon(
                    imageVector = when {
                        !hasQuery -> Icons.Rounded.Search
                        isFilterValid -> Icons.Rounded.CheckCircle
                        else -> Icons.Rounded.WarningAmber
                    },
                    contentDescription = "Search and filter status",
                    tint = when {
                        !hasQuery -> MaterialTheme.colorScheme.onSurfaceVariant
                        isFilterValid -> WarmGoldLive
                        else -> AmberAlert
                    }
                )
            },
            trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (hasQuery) {
                        IconButton(
                            onClick = { onFilterQueryChange("") },
                            modifier = Modifier.testTag("clear_filter_button")
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Clear,
                                contentDescription = "Clear filter"
                            )
                        }
                    }
                    IconButton(
                        onClick = { showFilterBuilder = true },
                        modifier = Modifier.testTag("filter_builder_button")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Tune,
                            contentDescription = "Structured criteria filter"
                        )
                    }
                    IconButton(
                        onClick = { showFilterHelp = true },
                        modifier = Modifier.testTag("filter_help_button")
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.HelpOutline,
                            contentDescription = "Filter syntax help"
                        )
                    }
                }
            },
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { focusManager.clearFocus() }),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = borderColor,
                unfocusedBorderColor = borderColor,
                focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow
            ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("display_filter_input")
        )

        if (hasQuery && !isFilterValid && uiState.filterValidation.errorHint != null) {
            Text(
                text = "${uiState.filterValidation.errorHint} — matching as keyword & payload search",
                style = MaterialTheme.typography.labelSmall,
                color = AmberAlert,
                modifier = Modifier.padding(start = 6.dp, top = 4.dp)
            )
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            QuickFilter.entries.forEach { filter ->
                val selected = uiState.quickFilter == filter
                FilterChip(
                    selected = selected,
                    onClick = { onQuickFilterSelected(filter) },
                    label = {
                        Text(
                            text = filter.label,
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium
                            )
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer
                    ),
                    modifier = Modifier.testTag("quick_filter_${filter.name.lowercase()}")
                )
            }
        }

        if (uiState.packets.isEmpty()) {
            EmptyCaptureView(
                isCapturing = uiState.isCapturing,
                hasActiveFilter = hasQuery || uiState.quickFilter != QuickFilter.ALL,
                totalCaptured = uiState.totalPacketCount,
                probeBusy = probeBusy,
                onStartCapture = onStartCapture,
                onOpenPcap = onOpenPcap,
                onRunProbe = onRunProbe,
                onResetFilters = {
                    onFilterQueryChange("")
                    onQuickFilterSelected(QuickFilter.ALL)
                },
                modifier = Modifier.weight(1f)
            )
        } else {
            LazyColumn(
                state = listState,
                verticalArrangement = Arrangement.spacedBy(6.dp),
                contentPadding = PaddingValues(bottom = 16.dp),
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .testTag("packet_list")
            ) {
                items(
                    items = uiState.packets,
                    key = { it.id }
                ) { packet ->
                    PacketRowCard(
                        packet = packet,
                        isSelected = packet.id == uiState.selectedPacketId,
                        resolveHostnames = uiState.resolveHostnames,
                        resolvedDomains = uiState.resolvedDomains,
                        onClick = { onSelectPacket(packet) }
                    )
                }
            }
        }
    }
}

@Composable
private fun CriteriaFilterDialog(
    currentQuickFilter: QuickFilter,
    onApply: (String, QuickFilter) -> Unit,
    onDismiss: () -> Unit
) {
    var srcIp by remember { mutableStateOf("") }
    var dstIp by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var payloadKeyword by remember { mutableStateOf("") }
    var selectedQuick by remember { mutableStateOf(currentQuickFilter) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Filter Packet Criteria",
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    QuickFilter.entries.forEach { q ->
                        FilterChip(
                            selected = selectedQuick == q,
                            onClick = { selectedQuick = q },
                            label = { Text(q.label) }
                        )
                    }
                }
                OutlinedTextField(
                    value = srcIp,
                    onValueChange = { srcIp = it },
                    label = { Text("Source IP (ip.src)") },
                    placeholder = { Text("e.g. 10.1.10.1") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_src_ip_input")
                )
                OutlinedTextField(
                    value = dstIp,
                    onValueChange = { dstIp = it },
                    label = { Text("Destination IP (ip.dst)") },
                    placeholder = { Text("e.g. 8.8.8.8") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_dst_ip_input")
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Port Number (src or dst)") },
                    placeholder = { Text("e.g. 443 or 53") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_port_input")
                )
                OutlinedTextField(
                    value = payloadKeyword,
                    onValueChange = { payloadKeyword = it },
                    label = { Text("Payload Keyword") },
                    placeholder = { Text("e.g. example.com or GET") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = MonoFontFamily),
                    modifier = Modifier.fillMaxWidth().testTag("criteria_payload_input")
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val clauses = buildList {
                        if (srcIp.isNotBlank()) add("ip.src == ${srcIp.trim()}")
                        if (dstIp.isNotBlank()) add("ip.dst == ${dstIp.trim()}")
                        if (port.isNotBlank()) add("port == ${port.trim()}")
                        if (payloadKeyword.isNotBlank()) add("payload contains \"${payloadKeyword.trim()}\"")
                    }
                    onApply(clauses.joinToString(" && "), selectedQuick)
                },
                modifier = Modifier.testTag("apply_criteria_button")
            ) {
                Text("Apply Filter")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
private fun TelemetrySummaryStrip(
    uiState: CaptureUiState,
    onToggleAutoScroll: () -> Unit,
    onToggleResolveHostnames: () -> Unit
) {
    val latestPps = uiState.throughputHistory.lastOrNull()?.packetsPerSec ?: 0
    val resolvedCount = uiState.resolvedDomains.size
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "${uiState.packets.size} shown",
                        style = MaterialTheme.typography.titleSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "• ${uiState.totalPacketCount} total",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "• ${formatByteCount(uiState.totalBytes)}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                val dnsStatus = if (uiState.resolveHostnames && resolvedCount > 0) " • $resolvedCount DNS" else ""
                Text(
                    text = if (uiState.isCapturing) {
                        "$latestPps pkt/s • tun0$dnsStatus"
                    } else {
                        "tun0 standby • $latestPps pkt/s$dnsStatus"
                    },
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            MiniThroughputSparkline(
                points = uiState.throughputHistory,
                modifier = Modifier
                    .width(68.dp)
                    .height(28.dp)
            )

            Surface(
                onClick = onToggleResolveHostnames,
                shape = RoundedCornerShape(8.dp),
                color = if (uiState.resolveHostnames) {
                    MaterialTheme.colorScheme.secondaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier
                    .heightIn(min = 36.dp)
                    .testTag("resolve_dns_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Dns,
                        contentDescription = "Toggle DNS IP-to-domain resolution",
                        tint = if (uiState.resolveHostnames) {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.size(15.dp)
                    )
                    Text(
                        text = "DNS",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.Bold
                        ),
                        color = if (uiState.resolveHostnames) {
                            MaterialTheme.colorScheme.onSecondaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        }
                    )
                }
            }

            Surface(
                onClick = onToggleAutoScroll,
                shape = RoundedCornerShape(8.dp),
                color = if (uiState.autoScroll) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier
                    .heightIn(min = 36.dp)
                    .testTag("autoscroll_toggle")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerticalAlignBottom,
                        contentDescription = "Auto-scroll to newest packets",
                        tint = if (uiState.autoScroll) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun PacketRowCard(
    packet: CapturedPacket,
    isSelected: Boolean,
    resolveHostnames: Boolean,
    resolvedDomains: Map<String, ResolvedHost>,
    onClick: () -> Unit
) {
    val protoColor = LocalProtocolColors.current.colorFor(packet.protocol)
    val bgColor = if (isSelected) {
        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.38f)
    } else {
        MaterialTheme.colorScheme.surfaceContainerLow
    }
    val borderColor = if (isSelected) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.7f)
    }

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = bgColor,
        border = BorderStroke(1.dp, borderColor),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .testTag("packet_row_${packet.id}")
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .heightIn(min = 68.dp)
                    .background(protoColor)
            )

            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
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
                        Text(
                            text = "#${packet.id}",
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.Bold
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = String.format("%.3fs", packet.relativeTimeMs / 1000.0),
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        ProtocolBadge(protocol = packet.protocol)
                        DirectionPill(direction = packet.direction)
                    }

                    Text(
                        text = "${packet.length} B",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                val srcText = if (packet.srcPort > 0) "${packet.srcIp}:${packet.srcPort}" else packet.srcIp
                val dstText = if (packet.dstPort > 0) "${packet.dstIp}:${packet.dstPort}" else packet.dstIp
                val srcResolved = if (resolveHostnames) resolvedDomains[packet.srcIp] else null
                val dstResolved = if (resolveHostnames) resolvedDomains[packet.dstIp] else null
                val srcDisplay = if (srcResolved != null) {
                    if (packet.srcPort > 0) "${srcResolved.domain}:${packet.srcPort}" else srcResolved.domain
                } else srcText
                val dstDisplay = if (dstResolved != null) {
                    if (packet.dstPort > 0) "${dstResolved.domain}:${packet.dstPort}" else dstResolved.domain
                } else dstText
                val anyResolved = srcResolved != null || dstResolved != null

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "$srcDisplay → $dstDisplay",
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = MonoFontFamily,
                            fontWeight = FontWeight.SemiBold
                        ),
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    if (!packet.hostOrSni.isNullOrBlank()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = packet.hostOrSni,
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = MonoFontFamily,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = protoColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                if (anyResolved) {
                    val sourceTag = (dstResolved ?: srcResolved)?.source?.shortLabel
                    Text(
                        text = "$srcText → $dstText${if (sourceTag != null) "  [$sourceTag]" else ""}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = MonoFontFamily),
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.85f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Text(
                    text = packet.infoSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun EmptyCaptureView(
    isCapturing: Boolean,
    hasActiveFilter: Boolean,
    totalCaptured: Long,
    probeBusy: Boolean,
    onStartCapture: () -> Unit,
    onOpenPcap: () -> Unit,
    onRunProbe: (ProbeType) -> Unit,
    onResetFilters: () -> Unit,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier.fillMaxWidth(),
        contentAlignment = Alignment.Center
    ) {
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = MaterialTheme.colorScheme.surfaceContainer,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 12.dp)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (hasActiveFilter && totalCaptured > 0) {
                    Icon(
                        imageVector = Icons.Rounded.Search,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                    Text(
                        text = "No Packets Match Display Filter",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "$totalCaptured packets captured in buffer, hidden by the active filter.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Button(onClick = onResetFilters) {
                        Text("Reset Display Filters")
                    }
                } else {
                    Image(
                        painter = painterResource(id = R.drawable.img_catfish_signals_1794857518067),
                        contentDescription = "Amazon Piraíba catfish catching wireless signal waves",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(172.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(ConsoleBgDark)
                    )
                    Text(
                        text = if (isCapturing) "Listening on tun0 (10.1.10.1)..." else stringResource(R.string.empty_capture_title),
                        style = MaterialTheme.typography.titleLarge
                    )
                    Text(
                        text = if (isCapturing) {
                            "Switch to any app on your device to inspect real traffic, or fire a live network probe below to generate DNS/TLS/HTTP packets immediately."
                        } else {
                            stringResource(R.string.empty_capture_subtitle)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (!isCapturing) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Button(
                                onClick = onStartCapture,
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("empty_start_capture_button")
                            ) {
                                Icon(Icons.Rounded.PlayArrow, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text("Start Capture")
                            }
                            OutlinedButton(
                                onClick = onOpenPcap,
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("empty_open_pcap_button")
                            ) {
                                Icon(Icons.Rounded.FolderOpen, contentDescription = null)
                                Spacer(Modifier.width(6.dp))
                                Text("Open .pcap")
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { onRunProbe(ProbeType.DNS_QUERY) },
                                enabled = !probeBusy,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                                ),
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("probe_dns_button")
                            ) {
                                Icon(Icons.Rounded.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("DNS Probe")
                            }
                            Button(
                                onClick = { onRunProbe(ProbeType.HTTPS_TLS) },
                                enabled = !probeBusy,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                                ),
                                modifier = Modifier
                                    .weight(1f)
                                    .heightIn(min = 48.dp)
                                    .testTag("probe_tls_button")
                            ) {
                                Icon(Icons.Rounded.Bolt, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("TLS Probe")
                            }
                        }
                    }
                }
            }
        }
    }
}
