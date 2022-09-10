package com.github.garyttierney.ghidrakt.plugin.shell

import org.jetbrains.kotlinx.ki.shell.Shell
import org.jetbrains.kotlinx.ki.shell.bound
import org.jetbrains.kotlinx.ki.shell.configuration.ReplConfigurationBase
import org.jline.reader.EndOfFileException
import org.jline.reader.UserInterruptException
import org.jline.utils.AttributedString
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.script.experimental.api.ResultValue
import kotlin.script.experimental.api.ScriptCompilationConfiguration
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.host.ScriptingHostConfiguration
import kotlin.script.experimental.jvm.KJvmEvaluatedSnippet
import kotlin.script.experimental.util.LinkedSnippet

// TODO: separate out the dependency on kotlinx's Shell class.
class KotlinScriptRepl(
    baseHostConfiguration: ScriptingHostConfiguration,
    baseCompilationConfiguration: ScriptCompilationConfiguration,
    baseEvaluationConfiguration: ScriptEvaluationConfiguration
) {
    private var running = AtomicBoolean(true)

    private val internal = KotlinScriptReplAdapter(
        object : ReplConfigurationBase() {},
        baseHostConfiguration,
        baseCompilationConfiguration,
        baseEvaluationConfiguration
    )

    val terminalOutputSource: InputStream
        get() = internal.terminalOutputReader

    val terminalInputSink: OutputStream
        get() = internal.terminalInputWriter

    fun print(message: String) = internal.reader.printAbove(message)
    fun print(message: AttributedString) = internal.reader.printAbove(message)

    fun repl() {
        internal.myInitEngine()

        while (running.get()) {
            try {
                val evaluationResult = when (val input = internal.read()) {
                    is ReplInput.Command -> {
                        continue
                    }

                    is ReplInput.Code -> {
                        internal.evaluate(input.code)
                    }

                    else -> continue
                }

                when (evaluationResult) {
                    is KotlinScriptReplEvaluationResult.Success -> {
                        val snippets = evaluationResult.result.value as LinkedSnippet<KJvmEvaluatedSnippet>

                        when (val evalResultValue = snippets.get().result) {
                            is ResultValue.Value -> {
                                print("${evalResultValue.name} = ${evalResultValue.value}".bound(internal.settings.maxResultLength))
                            }

                            is ResultValue.Error -> print(evalResultValue.error.localizedMessage)
                            else -> {}
                        }
                    }

                    is KotlinScriptReplEvaluationResult.Error -> {
                        evaluationResult.result.reports.forEach {
                            print(it.message)
                        }
                    }

                    is KotlinScriptReplEvaluationResult.Incomplete -> continue
                }
            } catch (e: UserInterruptException) {
                interrupt()
            } catch (ee: EndOfFileException) {
                continue
            } catch (ex: Exception) {
                // todo: logging
            }
        }
    }

    fun interrupt() {
        if (!internal.evalThread.isAlive) return
        internal.evalThread.interrupt()
        for (i in 1..5) {
            if (!internal.evalThread.isAlive) break
            Thread.sleep(100)
        }
        if (internal.evalThread.isAlive) {
            // NOTE: we cannot avoid thread killing here, because we're running arbitrary user code
            // see also jshell implementation, it uses low-level JDI stuff but in fact the same approach
            @Suppress("DEPRECATION")
            internal.evalThread.stop()
        }
        internal.evalThread = Shell.EvalThread()
    }

    fun run() {
        running.set(true)

        val thread = Thread { repl() }
        thread.start()
    }

    fun stop() = running.compareAndExchange(true, false)
}