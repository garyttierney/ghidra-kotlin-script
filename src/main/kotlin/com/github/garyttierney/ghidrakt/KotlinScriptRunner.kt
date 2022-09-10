package com.github.garyttierney.ghidrakt

import com.github.garyttierney.ghidrakt.api.GhidraKotlinScript
import com.github.garyttierney.ghidrakt.host.script.GhidraScriptEvaluationConfiguration
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI
import ghidra.app.script.GhidraScript
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection
import java.io.BufferedReader
import kotlin.script.experimental.host.toScriptSource
import kotlin.script.experimental.jvm.util.isError
import kotlin.script.experimental.jvm.util.isIncomplete
import kotlin.script.experimental.jvmhost.BasicJvmScriptingHost
import kotlin.script.experimental.jvmhost.createJvmCompilationConfigurationFromTemplate

class KotlinScriptRunner(private val host: BasicJvmScriptingHost) : GhidraScript(), KotlinScriptAPI {
    val decompiler: FlatDecompilerAPI
        get() = FlatDecompilerAPI(this)

    override var currentFunction: Function by this::currentFunction
    override var currentHighlight: ProgramSelection by this::currentHighlight
    override var currentLocation: ProgramLocation by this::currentLocation
    override var currentSelection: ProgramSelection by this::currentSelection
    override val program: Program by this::currentProgram

    override fun run() {
        val compileConfiguration = createJvmCompilationConfigurationFromTemplate<GhidraKotlinScript>()
        val evaluationConfiguration = GhidraScriptEvaluationConfiguration(this)
        val script = sourceFile.inputStream.bufferedReader().use(BufferedReader::readText)
        val result = host.eval(script.toScriptSource(sourceFile.name), compileConfiguration, evaluationConfiguration)

        if (result.isError() || result.isIncomplete()) {
            result.reports.forEach { printerr(it.message) }
        }
    }
}