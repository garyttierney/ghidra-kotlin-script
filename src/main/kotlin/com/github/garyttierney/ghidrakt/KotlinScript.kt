package com.github.garyttierney.ghidrakt

import com.github.garyttierney.ghidrakt.api.GhidraKotlinScript
import com.github.garyttierney.ghidrakt.api.GhidraKotlinScriptEvaluationConfiguration
import ghidra.app.script.GhidraScript
import java.io.BufferedReader
import kotlin.script.experimental.host.toScriptSource
import kotlin.script.experimental.jvmhost.BasicJvmScriptingHost
import kotlin.script.experimental.jvmhost.createJvmCompilationConfigurationFromTemplate

class KotlinScript(private val host: BasicJvmScriptingHost) : GhidraScript() {
    override fun run() {
        val compileConfiguration = createJvmCompilationConfigurationFromTemplate<GhidraKotlinScript>()
        val evaluationConfiguration = GhidraKotlinScriptEvaluationConfiguration(this)
        val script = sourceFile.inputStream.bufferedReader().use(BufferedReader::readText)

        host.eval(script.toScriptSource(sourceFile.name), compileConfiguration, evaluationConfiguration)
    }
}