package app.droplink.core.transfer

import app.droplink.core.protocol.AcceptMsg
import app.droplink.core.protocol.Checksums
import app.droplink.core.protocol.Frame
import app.droplink.core.protocol.FrameReader
import app.droplink.core.protocol.FrameType
import app.droplink.core.protocol.FrameWriter
import app.droplink.core.protocol.Hello
import app.droplink.core.protocol.Messages
import app.droplink.core.protocol.Protocol
import app.droplink.core.protocol.ProtocolException
import app.droplink.core.protocol.RemoteCancelException
import app.droplink.core.protocol.RemoteErrorException
import app.droplink.core.protocol.int
import app.droplink.core.protocol.long
import app.droplink.core.protocol.strOrNull
import app.droplink.core.protocol.bool
import app.droplink.core.security.Identity
import app.droplink.core.security.PairingCode
import app.droplink.core.security.PeerNotTrustedException
import app.droplink.core.security.Tls
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket

/** Where to connect. [socketFactory] lets QR mode bind sockets to the hotspot [android.net.Network]. */
data class Endpoint(
    val host: String,
    val port: Int,
    val socketFactory: SocketFactory = SocketFactory.getDefault(),
    /** Pinned receiver certificate (QR mode). Null = verify with the pairing code instead. */
    val expectedFingerprint: String? = null,
    val connectTimeoutMs: Int = 10_000,
)

interface SendListener {
    fun onConnected(peerFingerprint: String, pairingCode: String) {}
    fun onWaitingForApproval() {}
    fun onAccepted(accept: AcceptMsg) {}
    fun onFileStarted(index: Int, offset: Long) {}
    /** [position] = bytes of file [index] handed to the network so far. */
    fun onBytesSent(index: Int, position: Long) {}
    /** Receiver durably stored [bytes] of file [index]. */
    fun onConfirmed(index: Int, bytes: Long) {}
    fun onFileFinished(result: FileResult) {}
}

sealed class SendOutcome {
    data class Completed(val results: List<FileResult>) : SendOutcome() {
        val allOk get() = results.all { it.ok }
    }
    data class Declined(val reason: String) : SendOutcome()
    data class CancelledByPeer(val reason: String?) : SendOutcome()
    data object CancelledLocally : SendOutcome()
}

/**
 * Sends [files] over one TLS connection. Blocking: run it on a background thread.
 *
 * Retryable failures (Wi-Fi dropped, timeouts) throw a plain [IOException]; call again with
 * `hello.copy(resume = true)` and the receiver answers with the offsets it already has.
 * Non-retryable failures throw [FatalTransferException].
 */
class SenderSession(
    private val identity: Identity,
    private val endpoint: Endpoint,
    private val hello: Hello,
    private val files: List<OutgoingFile>,
    private val listener: SendListener,
    private val cancel: CancelToken,
) {
    init {
        require(files.size == hello.files.size) { "File list mismatch" }
    }

    private val control = LinkedBlockingQueue<Any>()

    fun run(): SendOutcome {
        cancel.throwIfCancelledAsOutcome()?.let { return it }
        val plain: Socket = endpoint.socketFactory.createSocket()
        cancel.register(plain)
        var ssl: SSLSocket? = null
        try {
            plain.tcpNoDelay = true
            runCatching { plain.sendBufferSize = 1 shl 20 }
            runCatching { plain.receiveBufferSize = 256 * 1024 }
            plain.connect(InetSocketAddress(endpoint.host, endpoint.port), endpoint.connectTimeoutMs)
            val context = Tls.context(identity, endpoint.expectedFingerprint)
            val socket = context.socketFactory.createSocket(plain, endpoint.host, endpoint.port, true) as SSLSocket
            ssl = socket
            cancel.register(socket)
            Tls.configure(socket)
            socket.useClientMode = true
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS
            try {
                socket.startHandshake()
            } catch (e: SSLHandshakeException) {
                val pin = generateSequence<Throwable>(e) { it.cause }.firstOrNull { it is PeerNotTrustedException }
                throw FatalTransferException(pin?.message ?: "Secure connection failed: ${e.message}", e)
            }
            return transfer(socket, plain)
        } catch (e: IOException) {
            if (cancel.isCancelled) return SendOutcome.CancelledLocally
            throw e
        } finally {
            runCatching { ssl?.close() }
            runCatching { plain.close() }
            ssl?.let { cancel.unregister(it) }
            cancel.unregister(plain)
        }
    }

    private fun transfer(socket: SSLSocket, plain: Socket): SendOutcome {
        val peerFingerprint = Tls.peerFingerprint(socket)
        listener.onConnected(peerFingerprint, PairingCode.of(peerFingerprint, identity.fingerprint))

        val reader = FrameReader(socket.inputStream)
        val writer = FrameWriter(socket.outputStream)
        cancel.onCancel { writer.writeJson(FrameType.CANCEL, Messages.cancel(cancel.reason)) }

        writer.writeJson(FrameType.HELLO, hello.toJson())
        listener.onWaitingForApproval()
        socket.soTimeout = APPROVAL_TIMEOUT_MS
        val answer = try {
            reader.expect(FrameType.ACCEPT, FrameType.DECLINE)
        } catch (e: RemoteCancelException) {
            return SendOutcome.CancelledByPeer(e.reason)
        } catch (e: RemoteErrorException) {
            throw FatalTransferException(e.message ?: "The other phone reported an error", e)
        }
        if (answer.type == FrameType.DECLINE) {
            return SendOutcome.Declined(answer.json().strOrNull("reason") ?: "Declined")
        }
        val accept = AcceptMsg.fromJson(answer.json(), files.size)
        listener.onAccepted(accept)

        socket.soTimeout = IO_TIMEOUT_MS
        startControlReader(reader, plain)

        val buffer = ByteArray(Protocol.BUFFER_SIZE)
        val results = ArrayList<FileResult>(files.size)
        try {
            for (i in files.indices) {
                pollControl()
                if (accept.done[i]) {
                    FileResult(i, ok = true, skipped = true).also { results += it; listener.onFileFinished(it) }
                    continue
                }
                results += sendFile(i, accept.offsets[i], writer, buffer)
            }
            writer.writeEmpty(FrameType.DONE)
            runCatching { awaitControl(FrameType.DONE, 15_000) } // a missing echo is not a failure
            return SendOutcome.Completed(results)
        } catch (e: RemoteCancelException) {
            return SendOutcome.CancelledByPeer(e.reason)
        } catch (e: RemoteErrorException) {
            throw FatalTransferException(e.message ?: "The other phone reported an error", e)
        } catch (e: ProtocolException) {
            throw FatalTransferException(e.message ?: "Protocol error", e)
        } catch (e: SourceChangedException) {
            runCatching { writer.writeJson(FrameType.ERROR, Messages.error(e.message ?: "Source changed")) }
            throw FatalTransferException(e.message ?: "File changed while sending", e)
        }
    }

    private fun sendFile(i: Int, offset: Long, writer: FrameWriter, buffer: ByteArray): FileResult {
        val entry = files[i].entry
        if (offset < 0 || offset > entry.size) throw ProtocolException("Receiver asked for an invalid offset")
        writer.writeJson(FrameType.FILE_START, Messages.fileStart(i, offset))
        listener.onFileStarted(i, offset)
        val digest = Checksums.sha256()
        var lastPing = now()
        val input = try {
            files[i].open()
        } catch (e: Exception) {
            throw SourceChangedException("Can't read ${entry.name}: ${e.message}")
        }
        input.use { stream ->
            // Resume: rebuild the hash of the part the receiver already has, without re-sending it.
            try {
                Checksums.update(digest, stream, offset, buffer) {
                    cancel.throwIfCancelled()
                    if (now() - lastPing > PING_INTERVAL_MS) {
                        writer.writeEmpty(FrameType.PING); lastPing = now()
                    }
                    pollControl()
                }
            } catch (e: java.io.EOFException) {
                throw SourceChangedException("${entry.name} got shorter while sending")
            }
            var position = offset
            var remaining = entry.size - offset
            while (remaining > 0) {
                cancel.throwIfCancelled()
                val n = stream.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                if (n < 0) throw SourceChangedException("${entry.name} got shorter while sending")
                writer.write(FrameType.DATA, buffer, 0, n, flush = false)
                digest.update(buffer, 0, n)
                position += n
                remaining -= n
                listener.onBytesSent(i, position)
                pollControl()
            }
        }
        writer.writeJson(FrameType.FILE_END, Messages.fileEnd(i, Checksums.hex(digest.digest())))
        val ack = awaitControl(FrameType.FILE_ACK, ACK_TIMEOUT_MS).json()
        if (ack.int("index") != i) throw ProtocolException("Acknowledgement for the wrong file")
        val result = FileResult(i, ack.bool("ok"), ack.strOrNull("reason"))
        listener.onFileFinished(result)
        return result
    }

    private fun startControlReader(reader: FrameReader, plain: Socket) {
        Thread({
            try {
                while (true) {
                    val f = reader.next()
                    when (f.type) {
                        FrameType.PROGRESS -> f.json().let { listener.onConfirmed(it.int("index"), it.long("bytes")) }
                        FrameType.PING -> Unit
                        else -> control.put(f)
                    }
                    if (f.type == FrameType.DONE || f.type == FrameType.CANCEL || f.type == FrameType.ERROR) break
                }
            } catch (t: Throwable) {
                control.put(t)
                // Unblock a writer that may be stuck on a dead connection.
                runCatching { plain.close() }
            }
        }, "droplink-send-ctl").apply { isDaemon = true }.start()
    }

    private fun handle(item: Any, expected: FrameType?): Frame? {
        if (item is Throwable) {
            throw item as? IOException ?: IOException(item.message, item)
        }
        val f = item as Frame
        return when (f.type) {
            expected -> f
            FrameType.CANCEL -> throw RemoteCancelException(Messages.cancelReason(f))
            FrameType.ERROR -> throw RemoteErrorException(Messages.errorMessage(f))
            else -> throw ProtocolException("Unexpected ${f.type} from receiver")
        }
    }

    private fun pollControl() {
        val item = control.poll() ?: return
        handle(item, null)
    }

    private fun awaitControl(type: FrameType, timeoutMs: Long): Frame {
        val deadline = now() + timeoutMs
        while (true) {
            cancel.throwIfCancelled()
            val left = deadline - now()
            if (left <= 0) throw IOException("Timed out waiting for the other phone")
            val item = control.poll(minOf(left, 500), TimeUnit.MILLISECONDS) ?: continue
            return handle(item, type)!!
        }
    }

    private fun CancelToken.throwIfCancelledAsOutcome(): SendOutcome? = if (isCancelled) SendOutcome.CancelledLocally else null

    companion object {
        const val HANDSHAKE_TIMEOUT_MS = 20_000
        const val APPROVAL_TIMEOUT_MS = 130_000
        const val IO_TIMEOUT_MS = 45_000
        const val ACK_TIMEOUT_MS = 120_000L
        const val PING_INTERVAL_MS = 5_000L
    }
}
