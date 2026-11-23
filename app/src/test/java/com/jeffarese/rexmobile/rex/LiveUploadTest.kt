package com.jeffarese.rexmobile.rex

import com.jeffarese.rexmobile.model.ConnStatus
import com.jeffarese.rexmobile.model.HostConfig
import com.jeffarese.rexmobile.model.HostConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Sends files to a block on a real Rex server the way picking a photo does: upload_begin for a
 * ticket, the file's bytes as raw binary messages on a bytes stream, one empty binary message to
 * end it, then the server types the path it stored it at. Skipped unless REX_LIVE_HOST is set; it
 * uploads into a throwaway shell and destroys its session at the end. Requires API revision 11.
 */
class LiveUploadTest {
    private val http = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS).pingInterval(15, TimeUnit.SECONDS).build()

    /** One file, in chunks small enough that the PNG crosses as several binary messages. */
    @Test
    fun uploadsAnImageAndItsPathIsTyped() = runBlocking {
        live("rex-mobile-upload-itest") { live ->
            val ticket = live.host.uploadBegin(live.sid, live.bid, "live-pixel.png", PNG.size.toLong())
            upload(live, ticket, PNG, chunk = 32)
            val screen = awaitText(live) { it.contains("uploads/") }
            val path = Regex("""\S*uploads/\S*""").findAll(screen).last().value
            assertTrue("a real path, not the ref: $path", path.startsWith("/") || path.startsWith("~/") || path.contains("live-pixel.png"))
        }
    }

    /** Two files begun as one batch, each of whose paths ends up typed. */
    @Test
    fun uploadsABatchAndBothPathsAreTyped() = runBlocking {
        live("rex-mobile-upload-batch-itest") { live ->
            val batch = UUID.randomUUID().toString()
            val names = listOf("batch-a.png", "batch-b.png")
            names.forEachIndexed { index, name ->
                val ticket = live.host.uploadBegin(live.sid, live.bid, name, PNG.size.toLong(), batch = batch, index = index, count = names.size)
                upload(live, ticket, PNG)
            }
            val screen = awaitText(live) { Regex("""\S*uploads/\S*""").findAll(it).count() >= names.size }
            val paths = Regex("""\S*uploads/\S*""").findAll(screen).map { it.value }.toList()
            assertTrue("a path per file: $paths", paths.toSet().size >= names.size)
            assertTrue(paths.all { it.startsWith("/") || it.startsWith("~/") })
        }
    }

    /** The bytes of [file] in [chunk]-sized messages, then the stream's end; the close must be 1000. */
    private suspend fun upload(live: Live, ticket: UploadTicket, file: ByteArray, chunk: Int = BytesStream.CHUNK_BYTES) {
        val stream = BytesStream(http, live.host.config.url, live.scope, { ticket.ticket }, object : BytesStreamListener {
            override fun onState(state: StreamState, detail: String?) = Unit
        })
        try {
            stream.start()
            withTimeout(20_000) {
                for (at in file.indices step chunk) stream.send(file.copyOfRange(at, minOf(at + chunk, file.size)))
                assertEquals(1000, stream.end())
            }
        } finally {
            stream.stop()
        }
    }

    /** The block's screen once [done] holds, failing after 15 s. */
    private suspend fun awaitText(live: Live, done: (String) -> Boolean): String {
        val until = System.currentTimeMillis() + 15_000
        while (true) {
            val screen = (live.host.blockMethod(live.sid, live.bid, "format", buildJsonObject {
                put("format", "text")
            }).jsonObject["content"]?.jsonPrimitive?.content).orEmpty()
            if (done(screen)) return screen
            assertTrue("timed out waiting on screen:\n$screen", System.currentTimeMillis() < until)
            delay(300)
        }
    }

    /** A connected host with a session whose first block is owned, for the length of [body]. */
    private suspend fun live(label: String, body: suspend (Live) -> Unit) {
        val address = System.getenv("REX_LIVE_HOST")
        assumeTrue("set REX_LIVE_HOST to run", !address.isNullOrBlank())
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val host = HostConnection(HostConfig(label = "live", url = ControlConnection.normalizeHostUrl(address!!)), http, scope) {}
        var sid: String? = null
        try {
            host.connect()
            withTimeout(20_000) { host.state.first { it.status == ConnStatus.ONLINE } }
            val s = host.newSession(label)!!.also { sid = it }
            val bid = withTimeout(10_000) {
                host.state.first { st -> st.views[s]?.windows?.firstOrNull()?.blocks?.isNotEmpty() == true }.views[s]!!
            }.windows!!.first().blocks.first().blockId
            host.ownBlock(s, bid)
            delay(800) // let the shell draw its prompt, so the typed path lands in it
            body(Live(host, scope, s, bid))
        } finally {
            sid?.let { runCatching { host.call("session.destroy", buildJsonObject { put("session_id", it) }) } }
            host.disconnect()
            delay(300)
            scope.cancel()
        }
    }

    private class Live(val host: HostConnection, val scope: CoroutineScope, val sid: String, val bid: String)

    private companion object {
        /** The smallest PNG, one transparent pixel. */
        val PNG = byteArrayOf(
            0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4.toByte(), 0x89.toByte(),
            0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C.toByte(), 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
            0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4.toByte(), 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE.toByte(),
            0x42, 0x60, 0x82.toByte(),
        )
    }
}
