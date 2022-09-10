package com.github.garyttierney.ghidrakt.plugin.shell

import org.jetbrains.kotlinx.ki.shell.*
import org.jetbrains.kotlinx.ki.shell.configuration.ReplConfiguration
import org.jetbrains.kotlinx.ki.shell.wrappers.ResultWrapper
import org.jline.reader.EndOfFileException
import org.jline.reader.LineReader
import org.jline.reader.LineReaderBuilder
import org.jline.reader.UserInterruptException
import org.jline.terminal.TerminalBuilder
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.time.Duration
import kotlin.script.experimental.api.ResultValue
import kotlin.script.experimental.api.ResultWithDiagnostics
import kotlin.script.experimental.api.ScriptCompilationConfiguration
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.host.ScriptingHostConfiguration
import kotlin.script.experimental.jvm.KJvmEvaluatedSnippet
import kotlin.script.experimental.util.LinkedSnippet

sealed class ReplInput {
    data class Code(val code: String) : ReplInput()
    data class Command(val commandLine: String) : ReplInput()
}

internal class KotlinScriptReplAdapter(
    replConfiguration: ReplConfiguration,
    baseHostConfiguration: ScriptingHostConfiguration,
    baseCompilationConfiguration: ScriptCompilationConfiguration,
    baseEvaluationConfiguration: ScriptEvaluationConfiguration
) : Shell(replConfiguration, baseHostConfiguration, baseCompilationConfiguration, baseEvaluationConfiguration) {

    private val terminalInputReader = PipedInputStream()
    val terminalInputWriter = PipedOutputStream()

    private val terminalOutputWriter = PipedOutputStream()
    val terminalOutputReader = PipedInputStream()

    private var blankLines = 0

    fun myInitEngine() {
        terminalInputReader.connect(terminalInputWriter)
        terminalOutputWriter.connect(terminalOutputReader)
        replConfiguration.load()

        settings = Settings(replConfiguration)

        val term = TerminalBuilder.builder().streams(terminalInputReader, terminalOutputWriter).build()

        readerBuilder =
            LineReaderBuilder.builder()
                .terminal(term)
                .highlighter(highlighter)
                .parser(parser)
                .completer(completer)
        reader = readerBuilder.build()

        replConfiguration.plugins().forEach { it.init(this, replConfiguration) }

        reader.autosuggestion
        reader.setVariable(
            LineReader.HISTORY_FILE, replConfiguration.get(
                LineReader.HISTORY_FILE,
                System.getProperty("user.home") + File.separator + ".ghidrashell_history"
            )
        )
        reader.setVariable(LineReader.SECONDARY_PROMPT_PATTERN, "")
        reader.option(LineReader.Option.DISABLE_EVENT_EXPANSION, true)
    }

    fun read() = reader.readLine(prompt())?.let {
        if (isCommandMode(it)) {
            ReplInput.Command(it)
        } else {
            ReplInput.Code(it)
        }
    }

    fun evaluate(line: String): KotlinScriptReplEvaluationResult {
        if (line.isBlank() && incompleteLines.isNotEmpty()) {
            if (blankLines == settings.blankLinesAllowed - 1) {
                incompleteLines.clear()
                reader.printAbove("You typed ${settings.blankLinesAllowed} blank lines. Starting a new command.")
            } else {
                blankLines++
            }

            return KotlinScriptReplEvaluationResult.Incomplete(Duration.ofNanos(1))
        } else {
            val source = (incompleteLines + line).joinToString(separator = "\n")
            val time = System.nanoTime()
            val result = eval(source)
            evaluationTimeMillis = (System.nanoTime() - time) / 1_000_000
            val duration = Duration.ofNanos(System.nanoTime() - time)

            return when (result.getStatus()) {
                ResultWrapper.Status.INCOMPLETE -> {
                    incompleteLines.add(line)
                    KotlinScriptReplEvaluationResult.Incomplete(duration)
                }

                ResultWrapper.Status.ERROR -> {
                    incompleteLines.clear()
                    KotlinScriptReplEvaluationResult.Error(duration, result.result)
                }

                ResultWrapper.Status.SUCCESS -> {
                    incompleteLines.clear()
                    KotlinScriptReplEvaluationResult.Success(
                        duration,
                        result.result as ResultWithDiagnostics.Success<*>
                    )
                }
            }
        }
    }

    private fun isCommandMode(buffer: String): Boolean = incompleteLines.isEmpty()
            && buffer.startsWith(":")
            && !buffer.startsWith("::")
}

