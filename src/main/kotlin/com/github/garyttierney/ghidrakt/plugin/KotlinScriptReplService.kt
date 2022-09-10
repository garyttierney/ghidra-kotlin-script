package com.github.garyttierney.ghidrakt.plugin

import ghidra.framework.plugintool.ServiceInfo
import java.io.InputStream
import java.io.OutputStream

@ServiceInfo(defaultProvider = [KotlinScriptReplPlugin::class])
interface KotlinScriptReplService {
    val terminalInputSink: OutputStream
    val terminalOutputSource: InputStream

    fun eval(code: String)

    fun start()

    fun stop()
}