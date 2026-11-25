package com.jeffarese.rexmobile.model

import com.jeffarese.rexmobile.FakeRex
import com.jeffarese.rexmobile.rex.TERMINAL_CREATOR
import com.jeffarese.rexmobile.rex.long
import com.jeffarese.rexmobile.rex.obj
import com.jeffarese.rexmobile.rex.str
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

/**
 * [ImageUpload]'s Result against [FakeRex]: upload_begin buys a ticket a rex.data.bytes.v1 stream
 * spends — the data handshake, the file's bytes as raw binary messages, one empty binary message,
 * then the server's close as the outcome. A server without uploads maps to Unsupported, a 1000
 * close to Done, anything else to Failed.
 */
class ImageUploadTest {
    private val rex = FakeRex("b1")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, _ -> })
    private val host = HostConnection(HostConfig(label = "fake", url = "https://fake.test"), rex, scope) {}
    private val uploader = ImageUpload(host, rex, scope)

    @After
    fun tearDown() {
        host.disconnect()
        scope.cancel()
    }

    private fun online() {
        host.connect()
        waitFor("online") { host.state.value.status == ConnStatus.ONLINE }
    }

    /** [bytes] through the read callback a buffer at a time, 0 once they run out. */
    private fun reader(bytes: ByteArray): suspend (ByteArray) -> Int {
        var at = 0
        return { buf ->
            val n = minOf(buf.size, bytes.size - at)
            if (n <= 0) 0 else {
                bytes.copyInto(buf, 0, at, at + n)
                at += n
                n
            }
        }
    }

    private fun upload(name: String, size: Long, bytes: ByteArray): ImageUpload.Result = runBlocking {
        uploader.upload("s1", "b1", name, size, reader(bytes))
    }

    @Test
    fun aHappyUploadStreamsTheBytesAndClosesDone() {
        online()
        assertEquals(11, host.apiRevision)
        val begins = CopyOnWriteArrayList<JsonObject>()
        val answer = rex.handle
        rex.handle = { method, payload ->
            answer(method, payload).also { if (method == "$TERMINAL_CREATOR.upload_begin") begins += payload }
        }
        val image = ByteArray(150_000) { it.toByte() }

        val result = upload("chart.png", image.size.toLong(), image)

        assertEquals(ImageUpload.Result.Done, result)
        assertEquals(1, rex.uploads.size)
        val sent = rex.uploads.single()
        assertTrue(sent.finished)
        assertEquals(image.size, sent.size)
        var at = 0
        sent.chunks.forEach {
            assertArrayEquals(image.copyOfRange(at, at + it.size), it)
            at += it.size
        }
        // upload_begin's payload names the session, the block and the file.
        val payload = begins.single()
        assertEquals("s1", payload.str("session_id"))
        assertEquals("b1", payload.str("block_id"))
        val args = payload.obj("args")!!
        assertEquals("chart.png", args.str("name"))
        assertEquals(image.size.toLong(), args.long("size"))
        assertTrue(args.str("ref")!!.startsWith("upload:"))
    }

    @Test
    fun aWelcomeWithoutARevisionLeavesItUnknown() {
        rex.apiRevision = null
        online()
        assertEquals(null, host.apiRevision)
    }

    @Test
    fun anOldServerWithoutUploadsAnswersUnsupported() {
        online()
        for (code in listOf("method_not_found", "revision_too_low")) {
            rex.uploadBeginError = code
            assertEquals(code, ImageUpload.Result.Unsupported, upload("a.png", 4L, byteArrayOf(1, 2, 3, 4)))
        }
        assertTrue(rex.uploads.isEmpty())
    }

    @Test
    fun anOversizeUploadFailsBeforeStreaming() {
        online()
        val result = upload("big.png", FakeRex.MAX_UPLOAD_BYTES + 1L, byteArrayOf(1))
        assertEquals(ImageUpload.Result.Failed("over the 100 MiB limit"), result)
        assertTrue(rex.uploads.isEmpty())
    }

    @Test
    fun aSourceEndingEarlyFailsInsteadOfReportingTruncatedBytesAsDone() {
        online()
        // Four bytes declared, only one in the source: the stream ends before it can close truncated.
        val result = upload("a.png", 4L, byteArrayOf(1))
        assertTrue(result is ImageUpload.Result.Failed && result.reason.contains("missing"))
        assertTrue(rex.uploads.none { it.finished })
    }

    @Test
    fun aNonOkCloseCodeFails() {
        online()
        rex.uploadCloseCode = 4_006
        rex.uploadCloseReason = "broke a rule"
        val result = upload("a.png", 8L, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))
        assertEquals(ImageUpload.Result.Failed("broke a rule"), result)
        assertTrue(rex.uploads.single().finished)
    }

    private fun waitFor(what: String, timeoutMs: Long = 10_000, done: () -> Boolean) {
        val until = System.currentTimeMillis() + timeoutMs
        while (!done()) {
            if (System.currentTimeMillis() > until) throw AssertionError("timed out waiting for $what")
            Thread.sleep(10)
        }
    }
}
