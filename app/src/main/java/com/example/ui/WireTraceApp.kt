package com.example.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Analytics
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.LightMode
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.SwapHoriz
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.R
import com.example.capture.AlertConfigStore
import com.example.capture.CaptureRepository
import com.example.model.QuickFilter
import com.example.ui.components.ExportPcapDialog
import com.example.ui.components.LiveCaptureIndicator
import com.example.ui.screens.AlertConfigScreen
import com.example.ui.screens.AnalyticsScreen
import com.example.ui.screens.CaptureScreen
import com.example.ui.screens.FollowStreamDialog
import com.example.ui.screens.PacketInspectorPane
import com.example.ui.screens.StreamsScreen
import com.example.ui.theme.WireTraceTheme
import com.example.viewmodel.WireTraceViewModel
import com.example.vpn.PacketCaptureVpnService
import kotlinx.coroutines.launch

private object WireTraceRoutes {
    const val PACKETS = "packets"
    const val INSPECTOR = "inspector"
    const val STREAMS = "streams"
    const val ANALYTICS = "analytics"
    const val ALERTS = "alerts"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WireTraceApp(
    viewModel: WireTraceViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val selectedPacket by viewModel.selectedPacket.collectAsStateWithLifecycle()
    val conversations by viewModel.conversations.collectAsStateWithLifecycle()
    val protocolStats by viewModel.protocolStats.collectAsStateWithLifecycle()
    val topHosts by viewModel.topHosts.collectAsStateWithLifecycle()
    val probeBusy by viewModel.probeBusy.collectAsStateWithLifecycle()
    val toastEvent by viewModel.toastEvent.collectAsStateWithLifecycle()
    val vpnStatus by CaptureRepository.statusMessage.collectAsStateWithLifecycle()
    val alertConfig by viewModel.alertConfig.collectAsStateWithLifecycle()
    val alertEvents by viewModel.alertEvents.collectAsStateWithLifecycle()
    val unreadAlertCount by viewModel.unreadAlertCount.collectAsStateWithLifecycle()
    val latestAlertEvent by viewModel.latestAlertEvent.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()
    val navController = rememberNavController()
    var showMenu by remember { mutableStateOf(false) }
    var showExportDialog by remember { mutableStateOf(false) }
    var pendingExportFilteredOnly by remember { mutableStateOf(false) }
    var followStreamKey by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        viewModel.bindAlertStore(context)
    }

    LaunchedEffect(toastEvent) {
        toastEvent?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            viewModel.consumeToast()
        }
    }

    LaunchedEffect(vpnStatus) {
        vpnStatus?.let { msg ->
            snackbarHostState.showSnackbar(msg)
            CaptureRepository.clearStatusMessage()
        }
    }

    LaunchedEffect(latestAlertEvent) {
        val evt = latestAlertEvent ?: return@LaunchedEffect
        if (alertConfig.notifySystemBar) {
            AlertConfigStore.showAlertNotification(context, evt)
        }
        viewModel.consumeLatestAlert()
        val res = snackbarHostState.showSnackbar(
            message = "Alert: ${evt.title}",
            actionLabel = "Alerts"
        )
        if (res == SnackbarResult.ActionPerformed) {
            navController.navigate(WireTraceRoutes.ALERTS) {
                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
        }
    }

    fun startVpnService() {
        val intent = Intent(context, PacketCaptureVpnService::class.java).apply {
            action = PacketCaptureVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpnService() {
        val intent = Intent(context, PacketCaptureVpnService::class.java).apply {
            action = PacketCaptureVpnService.ACTION_STOP
        }
        context.startService(intent)
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            CaptureRepository.onCaptureStopped("VPN consent is required to capture local packets")
        }
    }

    fun proceedWithVpnConsent() {
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ ->
        proceedWithVpnConsent()
    }

    val alertNotificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        viewModel.updateAlertConfig(alertConfig.copy(notifySystemBar = granted))
    }

    fun requestStartCapture() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        proceedWithVpnConsent()
    }

    val exportPcapLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")
    ) { uri ->
        uri?.let { viewModel.exportPcap(context.contentResolver, it, pendingExportFilteredOnly) }
    }

    val importPcapLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.importPcap(context.contentResolver, it) }
    }

    fun openExportDialog() {
        if (uiState.totalPacketCount == 0L) {
            coroutineScope.launch {
                snackbarHostState.showSnackbar("Capture or import packets first before exporting .pcap")
            }
        } else {
            showExportDialog = true
        }
    }

    WireTraceTheme(darkTheme = uiState.darkTheme) {
        if (showExportDialog) {
            ExportPcapDialog(
                totalCount = CaptureRepository.snapshotAllPackets().size,
                filteredCount = uiState.packets.size,
                hasActiveFilter = uiState.filterQuery.isNotBlank() || uiState.quickFilter != QuickFilter.ALL,
                totalBytes = uiState.totalBytes,
                onSaveToDevice = { fileName, filteredOnly ->
                    pendingExportFilteredOnly = filteredOnly
                    showExportDialog = false
                    exportPcapLauncher.launch(fileName)
                },
                onSharePcap = { fileName, filteredOnly ->
                    showExportDialog = false
                    viewModel.exportPcapForSharing(context, fileName, filteredOnly) { uri, count ->
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/vnd.tcpdump.pcap"
                            putExtra(Intent.EXTRA_STREAM, uri)
                            putExtra(Intent.EXTRA_SUBJECT, "Piraíba Capture ($count packets)")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(Intent.createChooser(shareIntent, "Share .pcap to Wireshark"))
                    }
                },
                onDismiss = { showExportDialog = false }
            )
        }
        if (followStreamKey != null) {
            val streamKey = followStreamKey!!
            val streamPackets = viewModel.packetsForStream(streamKey)
            FollowStreamDialog(
                streamKey = streamKey,
                packets = streamPackets,
                onFilterToStream = {
                    conversations.find { it.key == streamKey }?.let { stream ->
                        viewModel.filterToStream(stream)
                    }
                    followStreamKey = null
                    navController.navigate(WireTraceRoutes.PACKETS) {
                        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                        launchSingleTop = true
                    }
                },
                onDismiss = { followStreamKey = null }
            )
        }

        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val useRail = maxWidth >= 600.dp
            val isExpanded = maxWidth >= 840.dp
            val navBackStackEntry by navController.currentBackStackEntryAsState()
            val currentRoute = navBackStackEntry?.destination?.route ?: WireTraceRoutes.PACKETS

            fun navigateTab(route: String) {
                navController.navigate(route) {
                    popUpTo(navController.graph.findStartDestination().id) {
                        saveState = true
                    }
                    launchSingleTop = true
                    restoreState = true
                }
            }

            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing,
                snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
                topBar = {
                    TopAppBar(
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface,
                            titleContentColor = MaterialTheme.colorScheme.onSurface
                        ),
                        title = {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.app_name),
                                    style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold)
                                )
                                LiveCaptureIndicator(isCapturing = uiState.isCapturing)
                            }
                        },
                        actions = {
                            Button(
                                onClick = {
                                    if (uiState.isCapturing) stopVpnService() else requestStartCapture()
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (uiState.isCapturing) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                    contentColor = if (uiState.isCapturing) MaterialTheme.colorScheme.onError else MaterialTheme.colorScheme.onPrimary
                                ),
                                modifier = Modifier
                                    .padding(end = 4.dp)
                                    .testTag("start_stop_capture_button")
                            ) {
                                Icon(
                                    imageVector = if (uiState.isCapturing) Icons.Rounded.Stop else Icons.Rounded.PlayArrow,
                                    contentDescription = if (uiState.isCapturing) "Stop capture" else "Start capture",
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(Modifier.width(4.dp))
                                Text(
                                    text = if (uiState.isCapturing) {
                                        stringResource(R.string.action_stop_capture)
                                    } else {
                                        stringResource(R.string.action_start_capture)
                                    }
                                )
                            }

                            IconButton(
                                onClick = ::openExportDialog,
                                modifier = Modifier.testTag("export_pcap_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.FileDownload,
                                    contentDescription = stringResource(R.string.action_export_pcap)
                                )
                            }

                            Box {
                                IconButton(
                                    onClick = { showMenu = true },
                                    modifier = Modifier.testTag("top_menu_button")
                                ) {
                                    Icon(Icons.Rounded.MoreVert, contentDescription = "More options")
                                }
                                DropdownMenu(
                                    expanded = showMenu,
                                    onDismissRequest = { showMenu = false }
                                ) {
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.action_export_pcap)) },
                                        leadingIcon = { Icon(Icons.Rounded.FileDownload, contentDescription = null) },
                                        onClick = {
                                            showMenu = false
                                            openExportDialog()
                                        },
                                        modifier = Modifier.testTag("export_pcap_menu_item")
                                    )
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.action_import_pcap)) },
                                        leadingIcon = { Icon(Icons.Rounded.FolderOpen, contentDescription = null) },
                                        onClick = {
                                            showMenu = false
                                            importPcapLauncher.launch(arrayOf("*/*"))
                                        },
                                        modifier = Modifier.testTag("import_pcap_menu_item")
                                    )
                                    DropdownMenuItem(
                                        text = { Text(if (uiState.darkTheme) "Light Lab Theme" else "Dark Console Theme") },
                                        leadingIcon = {
                                            Icon(
                                                if (uiState.darkTheme) Icons.Rounded.LightMode else Icons.Rounded.DarkMode,
                                                contentDescription = null
                                            )
                                        },
                                        onClick = {
                                            showMenu = false
                                            viewModel.toggleTheme()
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.action_clear)) },
                                        leadingIcon = { Icon(Icons.Rounded.DeleteSweep, contentDescription = null) },
                                        onClick = {
                                            showMenu = false
                                            viewModel.clearCapture()
                                        },
                                        modifier = Modifier.testTag("clear_capture_menu_item")
                                    )
                                }
                            }
                        }
                    )
                },
                bottomBar = {
                    if (!useRail && currentRoute != WireTraceRoutes.INSPECTOR) {
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        ) {
                            NavigationBarItem(
                                selected = currentRoute == WireTraceRoutes.PACKETS,
                                onClick = { navigateTab(WireTraceRoutes.PACKETS) },
                                icon = { Icon(Icons.Rounded.Radar, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_packets)) },
                                modifier = Modifier.testTag("nav_packets")
                            )
                            NavigationBarItem(
                                selected = currentRoute == WireTraceRoutes.STREAMS,
                                onClick = { navigateTab(WireTraceRoutes.STREAMS) },
                                icon = { Icon(Icons.Rounded.SwapHoriz, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_streams)) },
                                modifier = Modifier.testTag("nav_streams")
                            )
                            NavigationBarItem(
                                selected = currentRoute == WireTraceRoutes.ANALYTICS,
                                onClick = { navigateTab(WireTraceRoutes.ANALYTICS) },
                                icon = { Icon(Icons.Rounded.Analytics, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_analytics)) },
                                modifier = Modifier.testTag("nav_analytics")
                            )
                            NavigationBarItem(
                                selected = currentRoute == WireTraceRoutes.ALERTS,
                                onClick = { navigateTab(WireTraceRoutes.ALERTS) },
                                icon = {
                                    BadgedBox(
                                        badge = {
                                            if (unreadAlertCount > 0) {
                                                Badge { Text("$unreadAlertCount") }
                                            }
                                        }
                                    ) {
                                        Icon(Icons.Rounded.NotificationsActive, contentDescription = null)
                                    }
                                },
                                label = { Text(stringResource(R.string.nav_alerts)) },
                                modifier = Modifier.testTag("nav_alerts")
                            )
                        }
                    }
                }
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    if (useRail) {
                        NavigationRail(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                        ) {
                            NavigationRailItem(
                                selected = currentRoute == WireTraceRoutes.PACKETS || currentRoute == WireTraceRoutes.INSPECTOR,
                                onClick = { navigateTab(WireTraceRoutes.PACKETS) },
                                icon = { Icon(Icons.Rounded.Radar, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_packets)) }
                            )
                            NavigationRailItem(
                                selected = currentRoute == WireTraceRoutes.STREAMS,
                                onClick = { navigateTab(WireTraceRoutes.STREAMS) },
                                icon = { Icon(Icons.Rounded.SwapHoriz, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_streams)) }
                            )
                            NavigationRailItem(
                                selected = currentRoute == WireTraceRoutes.ANALYTICS,
                                onClick = { navigateTab(WireTraceRoutes.ANALYTICS) },
                                icon = { Icon(Icons.Rounded.Analytics, contentDescription = null) },
                                label = { Text(stringResource(R.string.nav_analytics)) }
                            )
                            NavigationRailItem(
                                selected = currentRoute == WireTraceRoutes.ALERTS,
                                onClick = { navigateTab(WireTraceRoutes.ALERTS) },
                                icon = {
                                    BadgedBox(
                                        badge = {
                                            if (unreadAlertCount > 0) {
                                                Badge { Text("$unreadAlertCount") }
                                            }
                                        }
                                    ) {
                                        Icon(Icons.Rounded.NotificationsActive, contentDescription = null)
                                    }
                                },
                                label = { Text(stringResource(R.string.nav_alerts)) }
                            )
                        }
                        VerticalDivider()
                    }

                    NavHost(
                        navController = navController,
                        startDestination = WireTraceRoutes.PACKETS,
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight()
                    ) {
                        composable(WireTraceRoutes.PACKETS) {
                            if (isExpanded) {
                                Row(modifier = Modifier.fillMaxSize()) {
                                    CaptureScreen(
                                        uiState = uiState,
                                        probeBusy = probeBusy,
                                        onStartCapture = ::requestStartCapture,
                                        onOpenPcap = { importPcapLauncher.launch(arrayOf("*/*")) },
                                        onRunProbe = viewModel::runProbe,
                                        onFilterQueryChange = viewModel::setFilterQuery,
                                        onQuickFilterSelected = viewModel::setQuickFilter,
                                        onToggleAutoScroll = viewModel::toggleAutoScroll,
                                        onToggleResolveHostnames = viewModel::toggleResolveHostnames,
                                        onSelectPacket = { pkt -> viewModel.selectPacket(pkt.id) },
                                        modifier = Modifier.weight(0.52f)
                                    )
                                    VerticalDivider()
                                    PacketInspectorPane(
                                        packet = selectedPacket,
                                        resolvedDomains = uiState.resolvedDomains,
                                        resolveHostnames = uiState.resolveHostnames,
                                        showBackButton = false,
                                        onBack = {},
                                        onFollowStream = { key -> followStreamKey = key },
                                        onCopiedHex = { msg ->
                                            coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                                        },
                                        modifier = Modifier.weight(0.48f)
                                    )
                                }
                            } else {
                                CaptureScreen(
                                    uiState = uiState,
                                    probeBusy = probeBusy,
                                    onStartCapture = ::requestStartCapture,
                                    onOpenPcap = { importPcapLauncher.launch(arrayOf("*/*")) },
                                    onRunProbe = viewModel::runProbe,
                                    onFilterQueryChange = viewModel::setFilterQuery,
                                    onQuickFilterSelected = viewModel::setQuickFilter,
                                    onToggleAutoScroll = viewModel::toggleAutoScroll,
                                    onToggleResolveHostnames = viewModel::toggleResolveHostnames,
                                    onSelectPacket = { pkt ->
                                        viewModel.selectPacket(pkt.id)
                                        navController.navigate(WireTraceRoutes.INSPECTOR)
                                    }
                                )
                            }
                        }

                        composable(WireTraceRoutes.INSPECTOR) {
                            PacketInspectorPane(
                                packet = selectedPacket,
                                resolvedDomains = uiState.resolvedDomains,
                                resolveHostnames = uiState.resolveHostnames,
                                showBackButton = true,
                                onBack = { navController.popBackStack() },
                                onFollowStream = { key -> followStreamKey = key },
                                onCopiedHex = { msg ->
                                    coroutineScope.launch { snackbarHostState.showSnackbar(msg) }
                                }
                            )
                        }

                        composable(WireTraceRoutes.STREAMS) {
                            StreamsScreen(
                                streams = conversations,
                                onSelectStream = { stream -> followStreamKey = stream.key },
                                onFilterToStream = { stream ->
                                    viewModel.filterToStream(stream)
                                    navigateTab(WireTraceRoutes.PACKETS)
                                }
                            )
                        }

                        composable(WireTraceRoutes.ANALYTICS) {
                            AnalyticsScreen(
                                uiState = uiState,
                                protocolStats = protocolStats,
                                conversations = conversations,
                                topHosts = topHosts,
                                probeBusy = probeBusy,
                                onRunProbe = viewModel::runProbe,
                                onSelectConnection = { stream -> followStreamKey = stream.key },
                                onFilterHost = { host ->
                                    viewModel.setFilterQuery("host contains \"$host\"")
                                    navigateTab(WireTraceRoutes.PACKETS)
                                },
                                onFilterIp = { ip ->
                                    viewModel.setFilterQuery("ip.addr == $ip")
                                    navigateTab(WireTraceRoutes.PACKETS)
                                }
                            )
                        }

                        composable(WireTraceRoutes.ALERTS) {
                            AlertConfigScreen(
                                config = alertConfig,
                                alerts = alertEvents,
                                onUpdateConfig = viewModel::updateAlertConfig,
                                onAddPort = viewModel::addMonitoredPort,
                                onRemovePort = viewModel::removeMonitoredPort,
                                onToggleSystemNotifications = { enable ->
                                    if (enable && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                        val granted = ContextCompat.checkSelfPermission(
                                            context,
                                            Manifest.permission.POST_NOTIFICATIONS
                                        ) == PackageManager.PERMISSION_GRANTED
                                        if (!granted) {
                                            alertNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                            return@AlertConfigScreen
                                        }
                                    }
                                    viewModel.updateAlertConfig(alertConfig.copy(notifySystemBar = enable))
                                },
                                onResetDefaults = viewModel::resetAlertDefaults,
                                onClearAlerts = viewModel::clearAlerts,
                                onInspectAlert = { event ->
                                    event.filterExpr?.let { viewModel.setFilterQuery(it) }
                                    event.packetId?.let { viewModel.selectPacket(it) }
                                    navigateTab(WireTraceRoutes.PACKETS)
                                },
                                onScreenViewed = viewModel::markAlertsRead
                            )
                        }
                    }
                }
            }
        }
    }
}
