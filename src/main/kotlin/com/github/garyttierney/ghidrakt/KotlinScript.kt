package com.github.garyttierney.ghidrakt

import com.github.garyttierney.ghidrakt.api.GhidraKotlinScript
import com.github.garyttierney.ghidrakt.host.GhidraKotlinScriptEvaluationConfiguration
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI
import ghidra.app.script.GhidraScript
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import java.io.BufferedReader
import kotlin.script.experimental.host.toScriptSource
import kotlin.script.experimental.jvm.util.isError
import kotlin.script.experimental.jvm.util.isIncomplete
import kotlin.script.experimental.jvmhost.BasicJvmScriptingHost
import kotlin.script.experimental.jvmhost.createJvmCompilationConfigurationFromTemplate

class KotlinScript(private val host: BasicJvmScriptingHost) : GhidraScript() {
    val decompiler: FlatDecompilerAPI
        get() = FlatDecompilerAPI(this)

    var currentLocation: ProgramLocation by this::currentLocation
    var currentSelection: ProgramSelection by this::currentSelection
    var currentAddress: Address by this::currentAddress
    var currentFunction: Function by this::currentFunction

    override fun run() {
        val compileConfiguration = createJvmCompilationConfigurationFromTemplate<GhidraKotlinScript>()
        val evaluationConfiguration = GhidraKotlinScriptEvaluationConfiguration(this)
        val script = sourceFile.inputStream.bufferedReader().use(BufferedReader::readText)
        val result = host.eval(script.toScriptSource(sourceFile.name), compileConfiguration, evaluationConfiguration)

        if (result.isError() || result.isIncomplete()) {
            result.reports.forEach { printerr(it.message) }
        }
    }
}