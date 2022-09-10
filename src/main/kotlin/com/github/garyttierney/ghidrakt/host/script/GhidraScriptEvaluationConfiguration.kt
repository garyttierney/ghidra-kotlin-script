package com.github.garyttierney.ghidrakt.host.script

import com.github.garyttierney.ghidrakt.KotlinScriptAPI
import kotlin.script.experimental.api.ScriptEvaluationConfiguration
import kotlin.script.experimental.api.implicitReceivers

class GhidraScriptEvaluationConfiguration(api: KotlinScriptAPI) : ScriptEvaluationConfiguration({
    implicitReceivers(api)
})