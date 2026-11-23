package com.jeffarese.rexmobile

import com.jeffarese.rexmobile.rex.BYTES_SUBPROTOCOL
import com.jeffarese.rexmobile.rex.CONTROL_PROTOCOL
import com.jeffarese.rexmobile.rex.TERMINAL_CREATOR
import com.jeffarese.rexmobile.rex.obj
import com.jeffarese.rexmobile.rex.str
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicLong

/**
 * A Rex server inside the test, behind an OkHttpClient: control and data sockets without a network.
 * One session, "s1", with one window of terminal [blocks]. Requests are answered by [handle], which
 * a test can wrap to hold or fail a reply; events, drops and closes are sent from the test. Messages
 * to the app arrive on one thread per socket, in order, as OkHttp delivers them.
 */
class FakeRex(vararg blockIds: String = arrayOf("b1")) : OkHttpClient() {
    class Block(val id: String) {
        @Volatile var title = ""
        @Volatile var statuses: List<JsonObject> = emptyList()
        /** What terminal.format returns, as escape sequences. */
        @Volatile var screen = ""
    }

    val blocks = blockIds.map { Block(it) }
    fun block(id: String) = blocks.first { it.id == id }

    val controls = CopyOnWriteArrayList<Control>()
    val datas = CopyOnWriteArrayList<Data>()
    /** Every upload stream opened, in order. */
    val uploads = CopyOnWriteArrayList<Upload>()
    /** Every request's method, in order. */
    val calls = CopyOnWriteArrayList<String>()
    /** The byte ranges of redraws read through blob_read, from and to. */
    val blobReads = CopyOnWriteArrayList<LongRange>()

    /** The session view's revision, as session.view returns it. */
    @Volatile var revision = 1L
    /** The remote terminal's size, sent after each fresh snapshot. */
    @Volatile var columns = 80
    @Volatile var rows = 24
    /** Whether a data connection may resume its stream, as within the server's keep time. */
    @Volatile var resumable = true
    /** The API revision each welcome reports; servers that don't speak uploads send none. */
    @Volatile var apiRevision: Int? = 11
    /** Whether a fresh stream's snapshot waits for [Data.endSnapshot], as a long one over a slow link does. */
    @Volatile var slowSnapshots = false
    /** The error code upload_begin answers with, as on a server without uploads. */
    @Volatile var uploadBeginError: String? = null
    /** The close an upload stream sends once the empty message ends the upload. */
    @Volatile var uploadCloseCode = 1000
    @Volatile var uploadCloseReason = "ok"
    /** What a fresh stream starts with: by default nothing the app can read, which it redraws instead. */
    @Volatile var snapshot: ByteArray = "SNAPSHOT".toByteArray()
    /** What a fresh stream sends right after its snapshot ends, in the same burst. */
    @Volatile var afterSnapshot: (Data.() -> Unit)? = null

    /** Answers a request: a result, or a future completed with [Fail] for an error. */
    @Volatile var handle: (method: String, payload: JsonObject) -> CompletableFuture<JsonElement> = ::answer

    class Fail(val code: String, message: String, val status: Int = if (code.endsWith("not_found")) 404 else 500) : Exception(message)

    /** Whether a connection to this URL fails, as a closed port does. */
    @Volatile var refuses: (okhttp3.HttpUrl) -> Boolean = { false }

    override fun newWebSocket(request: Request, listener: WebSocketListener): WebSocket =
        if (refuses(request.url)) Control(request, listener).also { it.drop() }
        else if (request.url.encodedPath.endsWith("/api/control")) Control(request, listener).also { controls += it; it.open() }
        else if (request.header("Sec-WebSocket-Protocol") == BYTES_SUBPROTOCOL) Upload(request, listener).also { uploads += it; it.open() }
        else Data(request, listener).also { datas += it; it.open() }

    fun count(method: String) = calls.count { it == method }

    /** The default answers, from the session and [blocks]. */
    fun answer(method: String, payload: JsonObject): CompletableFuture<JsonElement> {
        val args = payload.obj("args") ?: JsonObject(emptyMap())
        val block = payload.str("block_id")?.let { id -> blocks.firstOrNull { it.id == id } }
        val result: JsonElement = when (method) {
            "server.version" -> buildJsonObject { put("version", "fake") }
            "session.list" -> buildJsonObject { putJsonArray("sessions") { add(session()) } }
            "session.bootstrap" -> buildJsonObject {
                put("client_id", "c1")
                putJsonArray("attached_sessions") { add(buildJsonObject { put("session", session()); put("view", view()) }) }
            }
            "session.view" -> view()
            "session.own_block", "session.disown_block" -> JsonObject(emptyMap())
            "data.connect" -> buildJsonObject {
                put("ticket", Base64.getUrlEncoder().encodeToString(ByteArray(16) { it.toByte() }))
                put("expires_in_ms", 30_000)
            }
            "$TERMINAL_CREATOR.title" -> buildJsonObject { put("title", block!!.title) }
            "$TERMINAL_CREATOR.pwd" -> buildJsonObject { put("pwd", "/tmp") }
            "$TERMINAL_CREATOR.process" -> buildJsonObject { putJsonObject("foreground") { put("pid", 1); put("name", "zsh") } }
            "$TERMINAL_CREATOR.program_status" -> buildJsonObject { putJsonArray("records") { block!!.statuses.forEach { add(it) } } }
            "$TERMINAL_CREATOR.size" -> buildJsonObject { put("columns", columns); put("rows", rows) }
            "$TERMINAL_CREATOR.format" -> format(block!!, args)
            "$TERMINAL_CREATOR.blob_read" -> blobRead(args)
            "$TERMINAL_CREATOR.upload_begin" -> return uploadBegin(args)
            else -> JsonObject(emptyMap())
        }
        return CompletableFuture.completedFuture(result)
    }

    private fun session() = buildJsonObject {
        put("session_id", "s1")
        put("label", "one")
    }

    // Uploads get a ticket only an upload stream can spend.
    private val uploadTickets = Collections.synchronizedSet(HashSet<String>())
    private val nextUploadTicket = AtomicLong(1)

    /** An upload_begin answer: a ticket for the bytes stream, or the error an old server gives. */
    private fun uploadBegin(args: JsonObject): CompletableFuture<JsonElement> {
        val fail = uploadBeginError
        if (fail != null) {
            return CompletableFuture.failedFuture(Fail(fail, "upload_begin is not supported"))
        }
        val size = (args["size"] as? JsonPrimitive)?.long ?: 0
        if (size > MAX_UPLOAD_BYTES) {
            return CompletableFuture.failedFuture(Fail("too_large", "upload is larger than 100MiB"))
        }
        val ticket = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putLong(nextUploadTicket.getAndIncrement()).putLong(0x726578L).array()
        val encoded = Base64.getUrlEncoder().encodeToString(ticket)
        uploadTickets += encoded
        return CompletableFuture.completedFuture(buildJsonObject {
            put("ticket", encoded)
            put("expires_in_ms", 30_000)
        })
    }

    private fun view() = buildJsonObject {
        put("revision", revision)
        put("session_id", "s1")
        putJsonArray("windows") {
            add(buildJsonObject {
                put("window_id", "w1")
                putJsonArray("layers") {
                    add(buildJsonObject {
                        put("kind", "tiled")
                        putJsonArray("blocks") {
                            blocks.forEach { b -> add(buildJsonObject { put("block_id", b.id); put("creator_name", TERMINAL_CREATOR) }) }
                        }
                    })
                }
            })
        }
    }

    // A redraw too large for one reply is kept, as the server keeps it, and read in parts.
    private val results = HashMap<Long, ByteArray>()
    private val nextResult = AtomicLong(1)

    private fun format(block: Block, args: JsonObject): JsonElement {
        val bytes = block.screen.toByteArray()
        val max = (args["max_bytes"] as? JsonPrimitive)?.long ?: 0
        if (max == 0L || bytes.size <= max) return buildJsonObject {
            put("content", block.screen)
            if (max > 0) put("total", bytes.size)
        }
        val id = nextResult.getAndIncrement()
        synchronized(results) { results[id] = bytes }
        val end = charEnd(bytes, max.toInt())
        return buildJsonObject {
            put("content", String(bytes, 0, end, Charsets.UTF_8))
            put("id", id)
            put("total", bytes.size)
            put("eof", false)
        }
    }

    /** Raw bytes stand in for the JSON-encoded size the server limits: an offset inside a character reads as a replacement character per byte. */
    private fun blobRead(args: JsonObject): JsonElement {
        val id = args["id"]!!.jsonPrimitive.long
        val bytes = synchronized(results) { results.getValue(id) }
        val from = args["offset"]!!.jsonPrimitive.long.toInt().coerceAtMost(bytes.size)
        val max = (args["max_bytes"] as? JsonPrimitive)?.long?.toInt()?.takeIf { it > 0 } ?: 49_152
        var end = charEnd(bytes, minOf(bytes.size.toLong(), from.toLong() + max).toInt())
        if (end <= from && from < bytes.size) end = minOf(bytes.size, from + 4)
        blobReads += from.toLong() until end.toLong()
        return buildJsonObject {
            put("id", id)
            put("data", String(bytes, from, end - from, Charsets.UTF_8))
            put("total", bytes.size)
            put("eof", end >= bytes.size)
        }
    }

    /** The end at or before [at] that doesn't cut a character. */
    private fun charEnd(bytes: ByteArray, at: Int): Int {
        var end = at.coerceAtMost(bytes.size)
        while (end in 1 until bytes.size && bytes[end].toInt() and 0xc0 == 0x80) end--
        return end
    }

    abstract class Socket(private val request: Request, protected val listener: WebSocketListener) : WebSocket {
        private val thread = Executors.newSingleThreadExecutor()
        /** Closed or dropped: nothing more is delivered. */
        @Volatile var ended = false
            private set

        fun open() = post {
            listener.onOpen(this, Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(101).message("Switching Protocols").build())
        }

        /** Deliver to the app on this socket's thread, unless it has ended by then. */
        protected fun post(block: () -> Unit) {
            try {
                thread.execute { if (!ended) block() }
            } catch (e: RejectedExecutionException) {
                // Ended.
            }
        }

        private fun end(block: () -> Unit) {
            synchronized(this) {
                if (ended) return
                ended = true
            }
            thread.execute(block)
            thread.shutdown()
        }

        override fun request() = request
        override fun queueSize() = 0L

        override fun send(text: String): Boolean {
            if (ended) return false
            post { receive(text) }
            return true
        }

        override fun send(bytes: ByteString): Boolean {
            if (ended) return false
            post { receive(bytes.toByteArray()) }
            return true
        }

        override fun close(code: Int, reason: String?): Boolean {
            end { listener.onClosed(this, code, reason.orEmpty()) }
            return true
        }

        override fun cancel() = end { listener.onFailure(this, IOException("canceled"), null) }

        /** The connection is lost, as when the network changes. */
        fun drop() = end { listener.onFailure(this, IOException("connection lost"), null) }

        /** The server closes the connection with [code]. */
        fun serverClose(code: Int, reason: String = "") = end { listener.onClosing(this, code, reason) }

        protected open fun receive(text: String) = Unit
        protected open fun receive(bytes: ByteArray) = Unit
    }

    inner class Control(request: Request, listener: WebSocketListener) : Socket(request, listener) {
        private var seq = 0L
        /** The hello the app sent, once it has. */
        @Volatile var hello: JsonObject? = null
            private set

        override fun receive(text: String) {
            val msg = kotlinx.serialization.json.Json.parseToJsonElement(text).jsonObject
            if (msg.str("type") == "hello") hello = msg
            when (msg.str("type")) {
                "hello" -> listener.onMessage(this, buildJsonObject {
                    put("type", "welcome")
                    put("protocol", CONTROL_PROTOCOL)
                    apiRevision?.let { put("api_revision", it) }
                    putJsonObject("client") {
                        put("id", "c1")
                        put("reconnect_token", "token")
                        put("resumed", msg.str("reconnect_token") != null)
                    }
                }.toString())
                "request" -> {
                    val id = msg.str("id")!!
                    val method = msg.str("method")!!
                    calls += method
                    handle(method, msg.obj("payload") ?: JsonObject(emptyMap())).whenComplete { result, error ->
                        post {
                            listener.onMessage(this, buildJsonObject {
                                put("type", "response")
                                put("id", id)
                                if (error != null) {
                                    val fail = (error.cause ?: error) as? Fail
                                    putJsonObject("error") {
                                        put("code", fail?.code ?: "internal")
                                        put("message", error.message ?: "failed")
                                        put("status", fail?.status ?: 500)
                                    }
                                } else {
                                    put("payload", result ?: JsonNull)
                                }
                            }.toString())
                        }
                    }
                }
            }
        }

        /** Send an event, as the server does to every client. */
        fun event(payload: JsonObject) = post {
            listener.onMessage(this, buildJsonObject {
                put("type", "event")
                put("seq", ++seq)
                put("payload", payload)
            }.toString())
        }

        /** Say the session's view changed, as when a pane is split or a tab added. */
        fun viewChanged(revision: Long) = event(buildJsonObject {
            put("type", "session_event")
            putJsonObject("payload") {
                put("session_id", "s1")
                putJsonObject("event") {
                    put("type", "session_view_changed")
                    putJsonObject("payload") { put("revision", revision) }
                }
            }
        })

        /** Send a terminal block's event, such as "program_status_changed". */
        fun blockEvent(blockId: String, name: String, data: JsonObject) = event(buildJsonObject {
            put("type", "session_event")
            putJsonObject("payload") {
                put("session_id", "s1")
                putJsonObject("event") {
                    put("type", "block_event")
                    putJsonObject("payload") {
                        put("block_id", blockId)
                        put("creator_name", TERMINAL_CREATOR)
                        put("name", name)
                        put("payload", data)
                    }
                }
            }
        })
    }

    inner class Data(request: Request, listener: WebSocketListener) : Socket(request, listener) {
        private val nonce = 0x1234L
        /** Whether this connection resumed a stream rather than starting one. */
        @Volatile var resumed = false
            private set

        override fun receive(bytes: ByteArray) {
            when (bytes[0].toInt()) {
                0x01 -> {
                    welcome()
                    // The snapshot, then the first message, which ends it.
                    output(snapshot)
                    if (!slowSnapshots) {
                        endSnapshot()
                        afterSnapshot?.invoke(this)
                    }
                }
                0x02 -> if (resumable) {
                    resumed = true
                    welcome()
                } else {
                    listener.onMessage(this, byteArrayOf(0x82.toByte(), 3).toByteString())
                }
            }
        }

        private fun welcome() = listener.onMessage(this, welcomeFrame(nonce))

        /** Program output, or anything else on the stream. */
        fun output(bytes: ByteArray) = post { listener.onMessage(this, bytes.toByteString()) }

        /** The first message, which ends the snapshot. */
        fun endSnapshot() = message(buildJsonObject { put("type", "resize"); put("cols", columns); put("rows", rows) })

        fun message(msg: JsonObject) = output("\u001b_rex1;${nonce.toULong()};$msg\u001b\\".toByteArray())
    }

    /**
     * One upload stream: the same handshake as a terminal stream, then raw binary messages that are
     * the file's bytes. One empty binary message ends it; the close the server then sends carries
     * the outcome. An unknown ticket is rejected, as an expired one is.
     */
    inner class Upload(request: Request, listener: WebSocketListener) : Socket(request, listener) {
        private val nonce = 0x7777L
        private var welcomed = false
        /** The file's bytes, per binary message. */
        val chunks = CopyOnWriteArrayList<ByteArray>()
        /** Whether the empty message that ends the upload has arrived. */
        @Volatile var finished = false
            private set

        val size get() = chunks.sumOf { it.size }

        override fun receive(bytes: ByteArray) {
            if (finished) return
            if (!welcomed) {
                if (bytes.size == 17 && bytes[0] == 0x01.toByte()) {
                    val ticket = Base64.getUrlEncoder().encodeToString(bytes.copyOfRange(1, 17))
                    if (ticket in uploadTickets) {
                        uploadTickets -= ticket
                        welcomed = true
                        listener.onMessage(this, welcomeFrame(nonce))
                    } else {
                        listener.onMessage(this, byteArrayOf(0x82.toByte(), 1).toByteString())
                    }
                }
                return
            }
            if (bytes.isEmpty()) {
                finished = true
                serverClose(uploadCloseCode, uploadCloseReason)
                return
            }
            chunks += bytes
        }
    }

    /** The 32-byte WELCOME frame of a data handshake. */
    private fun welcomeFrame(nonce: Long): ByteString {
        val w = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN)
        w.put(0x81.toByte()).put(ByteArray(16) { 7 })
        w.putInt(20, 60_000).putLong(24, nonce)
        return w.array().toByteString()
    }

    companion object {
        /** The largest upload_begin size the server accepts: 100MiB. */
        const val MAX_UPLOAD_BYTES = 100 * 1024 * 1024

        /** A program's status record, as program_status lists it. */
        fun status(id: String, state: String, title: String? = null, at: String? = null) = buildJsonObject {
            put("id", id)
            put("state", state)
            if (title != null) put("title", title)
            if (at != null) put("updated_at", at)
        }
    }
}
