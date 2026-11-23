package com.jeffarese.rexmobile.model

import com.jeffarese.rexmobile.rex.BytesStream
import com.jeffarese.rexmobile.rex.BytesStreamListener
import com.jeffarese.rexmobile.rex.RexCallException
import com.jeffarese.rexmobile.rex.StreamState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient

/** The largest upload a server takes, which upload_begin declines beyond. */
private const val MAX_BYTES = 100L * 1024 * 1024

/** How long the handshake and the server's closing answer may each take. */
private const val REPLY_MS = 15_000L

/** Errors an upload_begin answer carries on a server that can't take uploads. */
private val UNSUPPORTED = setOf("method_not_found", "revision_too_low")

/**
 * Sends a file to a pane the server's own way: `upload_begin` asks for a ticket, a bytes stream
 * spends it on the file's bytes as raw binary messages, one empty message ends them, and the
 * server's own close says how it went — 1000 means it kept the file and typed its path into the
 * pane, so a finished upload needs nothing done here.
 */
class ImageUpload(val host: HostConnection, private val http: OkHttpClient, private val scope: CoroutineScope) {

    /** How one upload ended. [Done] means the server kept the file and typed its path into the pane. */
    sealed interface Result {
        data object Done : Result

        /** The server can't take uploads, as one before API revision 11. */
        data object Unsupported : Result

        /** It didn't finish, [reason] saying why in a few words. */
        data class Failed(val reason: String) : Result
    }

    /**
     * Upload [size] bytes named [name] to the pane, [read] filling the buffer until it answers 0 or
     * less, [onProgress] told each count sent. Only cancellation raises: every other way it can go
     * comes back as a [Result].
     */
    suspend fun upload(
        sessionId: String,
        blockId: String,
        name: String,
        size: Long,
        read: suspend (ByteArray) -> Int,
        onProgress: (Long) -> Unit = {},
    ): Result {
        if (size > MAX_BYTES) return Result.Failed("over the 100 MiB limit")
        return try {
            withContext(Dispatchers.IO) { send(sessionId, blockId, name, size, read, onProgress) }
        } catch (e: TimeoutCancellationException) {
            Result.Failed("no answer")
        } catch (e: CancellationException) {
            throw e
        } catch (e: RexCallException) {
            if (e.code in UNSUPPORTED) Result.Unsupported else Result.Failed(e.error.message.ifBlank { e.code })
        } catch (e: Exception) {
            Result.Failed(e.message ?: "couldn't upload")
        }
    }

    /** The ticket, then the bytes, then the server's close for the answer. */
    private suspend fun send(
        sessionId: String,
        blockId: String,
        name: String,
        size: Long,
        read: suspend (ByteArray) -> Int,
        onProgress: (Long) -> Unit,
    ): Result {
        val ticket = host.uploadBegin(sessionId, blockId, name, size)
        // The reason a close reports, set before the answer end() takes.
        var detail: String? = null
        val stream = BytesStream(http, host.config.url, scope, { ticket.ticket }, object : BytesStreamListener {
            override fun onState(state: StreamState, d: String?) {
                detail = d
            }
        })
        try {
            stream.start()
            // An empty send does nothing but wait for the handshake's answer, or throw a reject's.
            withTimeout(REPLY_MS) { stream.send(ByteArray(0)) }
            val buffer = ByteArray(BytesStream.CHUNK_BYTES)
            var sent = 0L
            while (sent < size) {
                val n = read(buffer)
                if (n <= 0) break
                // Never more than the size declared, whatever the source gives.
                val take = minOf(n, (size - sent).toInt())
                stream.send(buffer.copyOfRange(0, take))
                sent += take
                onProgress(sent)
            }
            return if (withTimeout(REPLY_MS) { stream.end() } == 1000) Result.Done
            else Result.Failed(detail?.takeIf { it.isNotBlank() } ?: "the upload didn't finish")
        } finally {
            stream.stop()
        }
    }
}
