package com.github.garyttierney.ghidrakt.api

import ghidra.app.script.GhidraScript
import kotlin.script.experimental.api.*
import kotlin.script.experimental.jvm.dependenciesFromClassContext
import kotlin.script.experimental.jvm.jvm

class GhidraKotlinScriptCompileConfiguration : ScriptCompilationConfiguration({
    implicitReceivers(GhidraScript::class)

    jvm {
        dependenciesFromClassContext(GhidraKotlinScript::class, wholeClasspath = true)
    }

    ide {
        acceptedLocations(ScriptAcceptedLocation.Everywhere)
    }
})