package com.github.garyttierney.ghidrakt.plugin.shell

import java.time.Duration
import kotlin.script.experimental.api.ResultWithDiagnostics

sealed class KotlinScriptReplEvaluationResult(val time: Duration) {
    class Success(time: Duration, val result: ResultWithDiagnostics.Success<*>) : KotlinScriptReplEvaluationResult(time)
    class Error(time: Duration, val result: ResultWithDiagnostics<*>) : KotlinScriptReplEvaluationResult(time)
    class Incomplete(time: Duration) : KotlinScriptReplEvaluationResult(time)
}