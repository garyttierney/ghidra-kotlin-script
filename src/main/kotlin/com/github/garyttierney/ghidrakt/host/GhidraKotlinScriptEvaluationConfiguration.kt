package com.github.garyttierney.ghidrakt.host

import com.github.garyttierney.ghidrakt.KotlinScript
import ghidra.app.script.GhidraScript
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.api.implicitReceivers

class GhidraKotlinScriptEvaluationConfiguration(script: KotlinScript) : ScriptEvaluationConfiguration({
    implicitReceivers(script)
})