package app.droplink.transfer

import android.content.Context
import app.droplink.core.protocol.Checksums
import app.droplink.core.protocol.Hello
import app.droplink.core.protocol.LedgerStore
import app.droplink.core.protocol.Protocol
import app.droplink.core.protocol.TransferMode
import app.droplink.core.security.IdentityFactory
import app.droplink.core.security.IdentityStore
import app.droplink.core.transfer.CancelToken
import app.droplink.core.transfer.Decision
import app.droplink.core.transfer.DirectorySinkFactory
import app.droplink.core.transfer.Endpoint
import app.droplink.core.transfer.IncomingRequest
import app.droplink.core.transfer.LocalOutgoingFile
import app.droplink.core.transfer.ReceiveCallbacks
import app.droplink.core.transfer.ReceiverServer
import app.droplink.core.transfer.SendOutcome
import app.droplink.core.transfer.SenderSession
import java.io.File
import java.net.InetAddress
import java.util.Random
import java.util.UUID

/**
 * Loopback self-test (Settings → "Run self-test"): a full TLS transfer over 127.0.0.1 on this phone.
 * Verifies that crypto, the protocol and storage work in this build (e.g. after R8) and measures the
 * local throughput ceiling of the phone's CPU/storage.
 */
object SelfTest {
    data class Result(val ok: Boolean, val bytes: Long, val millis: Long, val detail: String?) {
        val bytesPerSecond: Long get() = if (millis <= 0) 0 else bytes * 1000 / millis
    }

    fun run(context: Context, identity: IdentityStore, sizeBytes: Int = 64 shl 20): Result {
        val root = File(context.cacheDir, "selftest-" + UUID.randomUUID()).apply { mkdirs() }
        try {
            val src = File(root, "src.bin")
            src.outputStream().buffered(1 shl 20).use { out ->
                val buf = ByteArray(1 shl 20)
                val rnd = Random(42)
                var left = sizeBytes
                while (left > 0) {
                    rnd.nextBytes(buf)
                    val n = minOf(left, buf.size)
                    out.write(buf, 0, n)
                    left -= n
                }
            }
            val out = File(root, "out").apply { mkdirs() }
            val server = ReceiverServer(
                identity.get(), DirectorySinkFactory(out), LedgerStore(File(root, "ledger")),
                object : ReceiveCallbacks { override fun onIncoming(request: IncomingRequest) = Decision.Accept },
                preferredPort = 0, bindAddress = InetAddress.getLoopbackAddress(),
            )
            val port = server.start()
            try {
                val file = LocalOutgoingFile(src, "selftest.bin")
                val hello = Hello(Protocol.VERSION, "selftest-" + UUID.randomUUID(), "self-test", "selftest", TransferMode.LOOPBACK, false, listOf(file.entry))
                val started = System.currentTimeMillis()
                val outcome = SenderSession(
                    IdentityFactory.generate("self-test-sender"),
                    Endpoint("127.0.0.1", port, expectedFingerprint = identity.get().fingerprint),
                    hello, listOf(file), object : app.droplink.core.transfer.SendListener {}, CancelToken(),
                ).run()
                val millis = System.currentTimeMillis() - started
                val received = File(out, "selftest.bin")
                val ok = outcome is SendOutcome.Completed && outcome.allOk &&
                    received.length() == src.length() &&
                    Checksums.sha256Hex(received.inputStream()) == Checksums.sha256Hex(src.inputStream())
                return Result(ok, sizeBytes.toLong(), millis, if (ok) null else outcome.toString())
            } finally {
                server.stop(keepResumeState = false)
            }
        } catch (e: Exception) {
            return Result(false, 0, 0, e.javaClass.simpleName + ": " + e.message)
        } finally {
            root.deleteRecursively()
        }
    }
}
