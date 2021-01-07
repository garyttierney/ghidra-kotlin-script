package com.github.garyttierney.ghidrakt.api

import ghidra.app.script.GhidraScript
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.api.implicitReceivers

class GhidraKotlinScriptEvaluationConfiguration(script: GhidraScript) : ScriptEvaluationConfiguration({
    implicitReceivers(script)
})