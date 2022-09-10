package com.github.garyttierney.ghidrakt.plugin.shell.tty

import com.jediterm.terminal.Questioner
import com.jediterm.terminal.TtyConnector
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream


class StreamTtyConnector(terminalOutput: InputStream, private val terminalInputSink: OutputStream) :
    TtyConnector {

    val reader = InputStreamReader(terminalOutput)

    override fun init(q: Questioner): Boolean {
        return true
    }

    override fun close() {
        reader.close()
    }

    override fun getName(): String {
        return "ktshell"
    }

    override fun read(buf: CharArray, offset: Int, length: Int): Int {
        return reader.read(buf, offset, length)
    }

    override fun write(bytes: ByteArray) {
        terminalInputSink.write(bytes)
        terminalInputSink.flush()
    }

    override fun write(string: String) {
        write(string.toByteArray())
    }

    override fun isConnected(): Boolean {
        return true
    }

    override fun waitFor(): Int {
        return 0
    }

    override fun ready(): Boolean {
        return true
    }
}