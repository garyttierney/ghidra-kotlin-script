package com.github.garyttierney.ghidrakt.plugin

import com.github.garyttierney.ghidrakt.host.script.GhidraScriptCompilationConfiguration
import com.github.garyttierney.ghidrakt.host.script.GhidraScriptEvaluationConfiguration
import com.github.garyttierney.ghidrakt.plugin.shell.KotlinScriptRepl
import kotlinx.coroutines.Job
import org.jetbrains.kotlinx.ki.shell.configuration.ReplConfigurationBase
import java.io.InputStream
import java.io.OutputStream
import kotlin.script.experimental.jvm.defaultJvmScriptingHostConfiguration

class KotlinScriptReplServiceImpl(plugin: KotlinScriptReplPlugin) : KotlinScriptReplService {

    override val terminalOutputSource: InputStream
        get() = repl.terminalOutputSource

    override val terminalInputSink: OutputStream
        get() = repl.terminalInputSink

    private val repl: KotlinScriptRepl

    init {
        val compileConfiguration = GhidraScriptCompilationConfiguration()
        val evaluationConfiguration = GhidraScriptEvaluationConfiguration(plugin)

        repl = KotlinScriptRepl(
            defaultJvmScriptingHostConfiguration,
            compileConfiguration,
            evaluationConfiguration
        )
    }

    override fun eval(code: String) {
        TODO("Not yet implemented")
    }

    override fun start() {
        repl.run()
    }

    override fun stop() {
        repl.stop()
    }
}