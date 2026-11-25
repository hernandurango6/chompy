package com.jeffarese.rexmobile.rex

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.IOException
import java.util.concurrent.TimeUnit

interface BytesStreamListener {
    fun onState(state: StreamState, detail: String?)
}

/**
 * Sends raw bytes over a `rex.data.bytes.v1` data connection, such as a file an `upload_begin`
 * ticket was asked for. The socket starts with the usual handshake and then takes binary messages
 * of up to [CHUNK_BYTES]; the upload ends with one empty binary message, which the server answers
 * with its own close, 1000 for bytes it kept.
 *
 * An upload can't be resumed: once the socket drops the server saw part of a file, so [send] and
 * [end] fail rather than reconnect. Cancelling a [send] or [end] call leaves the stream open;
 * [stop] abandons it. Listener calls arrive on OkHttp's threads.
 */
class BytesStream(
    http: OkHttpClient,
    private val baseUrl: String,
    private val scope: CoroutineScope,
    private val getTicket: suspend () -> String,
    private val listener: BytesStreamListener,
) {
    // One that sends none already, such as a test's, is used as it is.
    private val client = if (http.pingIntervalMillis == 0) http else http.newBuilder().pingInterval(0, TimeUnit.SECONDS).build()
    private val lock = Any()
    private var ws: WebSocket? = null
    /** The handshake's answer; [send] and [end] wait for it. */
    private val ready = CompletableDeferred<Unit>()
    /** The server's own close, [end]'s answer. */
    private val closed = CompletableDeferred<Int>()
    @Volatile private var stopped = false
    @Volatile var state = StreamState.CONNECTING
        private set

    /** Connect, ask for the ticket and run the handshake. */
    fun start() {
        scope.launch {
            val hello = try {
                DataHandshake.hello(getTicket())
            } catch (e: Exception) {
                ensureActive()
                if (!stopped) fail(e)
                return@launch
            }
            if (!stopped) open { it.send(hello.toByteString()) }
        }
    }

    /** Give up on the upload: the socket is dropped without the empty message that ends it. */
    fun stop() {
        stopped = true
        dropSocket()
        ready.completeExceptionally(ConnectionClosedException("stopped"))
        closed.completeExceptionally(ConnectionClosedException("stopped"))
    }

    /** Queue [bytes] as binary messages of at most [CHUNK_BYTES], waiting while the socket holds too much. */
    suspend fun send(bytes: ByteArray) {
        ready.await()
        var off = 0
        while (off < bytes.size) {
            val n = minOf(CHUNK_BYTES, bytes.size - off)
            if (!socket().send(bytes.toByteString(off, n))) throw ConnectionClosedException("send failed")
            off += n
            while ((ws?.queueSize() ?: 0) > MAX_QUEUE_BYTES) delay(50)
        }
    }

    /**
     * End the upload with one empty binary message, then wait for the server's close and return its
     * code: 1000 for a file it kept. A server that already closed already gave its answer.
     */
    suspend fun end(): Int {
        ready.await()
        if (!closed.isCompleted && !socket().send(ByteString.EMPTY)) {
            // A close that landed with the send is the answer itself.
            if (!closed.isCompleted) throw ConnectionClosedException("send failed")
        }
        return closed.await()
    }

    private fun socket(): WebSocket =
        synchronized(lock) { ws } ?: throw ConnectionClosedException("connection closed")

    private fun open(handshake: (WebSocket) -> Unit) {
        val request = Request.Builder()
            .url("${ControlConnection.toWs(baseUrl)}/api/data")
            .header("Sec-WebSocket-Protocol", BYTES_SUBPROTOCOL)
            .build()
        var welcomed = false
        val socket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                handshake(webSocket)
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (welcomed || stopped) return
                when (val reply = DataHandshake.decode(bytes.toByteArray())) {
                    null -> return
                    is DataHandshake.Welcome -> {
                        welcomed = true
                        setState(StreamState.LIVE)
                        ready.complete(Unit)
                    }
                    is DataHandshake.Reject -> {
                        welcomed = true
                        val detail = DataHandshake.rejectReasons[reply.reason] ?: "rejected (${reply.reason})"
                        webSocket.close(1000, null)
                        fail(IOException(detail))
                    }
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                handleClose(code, reason, welcomed)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                handleClose(code, reason, welcomed)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (closed.isCompleted || stopped) return
                fail(IOException(t.message ?: "connection lost", t))
            }
        })
        // A stop() that landed while the socket connected already dropped nothing: cancel this one
        // instead of keeping it alive with a spent ticket.
        synchronized(lock) { if (!stopped) ws = socket else socket.cancel() }
    }

    private fun handleClose(code: Int, reason: String, welcomed: Boolean) {
        if (stopped || closed.isCompleted) return
        stopped = true
        forgetSocket()
        // The state first, so a listener's read of it can't lose to end()'s answer.
        if (!welcomed) fail(IOException(reason.ifBlank { "closed ($code)" }))
        else {
            setState(if (code == 1000) StreamState.ENDED else StreamState.FAILED, reason.ifBlank { "closed ($code)" })
            closed.complete(code)
        }
    }

    private fun fail(e: Exception) {
        stopped = true
        ready.completeExceptionally(e)
        closed.completeExceptionally(e)
        dropSocket()
        setState(StreamState.FAILED, e.message)
    }

    private fun setState(s: StreamState, detail: String? = null) {
        state = s
        listener.onState(s, detail)
    }

    private fun dropSocket() {
        synchronized(lock) { ws.also { ws = null } }?.cancel()
    }

    /** Releases the reference to a socket that already closed, without cancelling the close reply. */
    private fun forgetSocket() {
        synchronized(lock) { ws = null }
    }

    companion object {
        /** The largest binary message sent; [send] splits longer arrays into messages of this size. */
        const val CHUNK_BYTES = 64 * 1024
        /** How much the socket may hold unsent before [send] waits. */
        private const val MAX_QUEUE_BYTES = 4 * 1024 * 1024L
    }
}
