package app.droplink.core.protocol

/** The three ways two phones can reach each other. */
enum class ConnectionMode { LAN, WIFI_DIRECT, QR_HOTSPOT }

/** What the sender currently knows about a chosen peer and about its own phone. */
data class ModeInputs(
    /** The user forced a mode in the UI (null = automatic). */
    val forced: ConnectionMode? = null,
    /** The peer was discovered via NSD on the shared Wi-Fi network. */
    val peerOnLan: Boolean,
    /** The peer was seen in Wi-Fi Direct discovery. */
    val peerOnWifiDirect: Boolean,
    /** This phone has a working Wi-Fi Direct stack and the needed permission. */
    val wifiDirectUsable: Boolean,
)

/**
 * Auto-selection policy:
 *  1. both phones see each other on the LAN → LAN;
 *  2. otherwise try Wi-Fi Direct (bounded by [WIFI_DIRECT_TIMEOUT_MS]);
 *  3. finally fall back to the QR hotspot, which needs no shared network at all.
 * A forced mode is honoured on its own (no silent fallback: the user asked for it).
 */
object ModeSelector {
    const val WIFI_DIRECT_TIMEOUT_MS = 15_000L
    const val WIFI_DIRECT_ATTEMPTS = 2
    const val LAN_CONNECT_TIMEOUT_MS = 8_000

    fun plan(inputs: ModeInputs): List<ConnectionMode> {
        inputs.forced?.let { return listOf(it) }
        val plan = ArrayList<ConnectionMode>(3)
        if (inputs.peerOnLan) plan += ConnectionMode.LAN
        // Wi-Fi Direct needs the peer's P2P device address, so it is only an option when we saw it there.
        if (inputs.wifiDirectUsable && inputs.peerOnWifiDirect) plan += ConnectionMode.WIFI_DIRECT
        plan += ConnectionMode.QR_HOTSPOT
        return plan
    }

    /** The next mode to try after [failed] failed, or null if nothing is left. */
    fun next(plan: List<ConnectionMode>, failed: ConnectionMode): ConnectionMode? {
        val i = plan.indexOf(failed)
        return if (i < 0 || i + 1 >= plan.size) null else plan[i + 1]
    }

    /**
     * Whether the receiver should switch its QR hotspot on by default. Without a shared Wi-Fi network
     * the hotspot is the most reliable way in; on Wi-Fi, LAN discovery usually wins, and starting a
     * hotspot can knock some phones off their network, so it stays opt-in.
     */
    fun receiverPrefersQr(connectedToWifi: Boolean): Boolean = !connectedToWifi
}
