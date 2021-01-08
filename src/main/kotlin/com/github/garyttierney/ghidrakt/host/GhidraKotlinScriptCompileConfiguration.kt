package com.github.garyttierney.ghidrakt.host

import com.github.garyttierney.ghidrakt.KotlinScript
import ghidra.app.script.GhidraScript
import kotlin.script.experimental.api.*
import kotlin.script.experimental.jvm.dependenciesFromClassContext
import kotlin.script.experimental.jvm.jvm

class GhidraKotlinScriptCompileConfiguration : ScriptCompilationConfiguration({
    implicitReceivers(KotlinScript::class)

    jvm {
        dependenciesFromClassContext(GhidraKotlinScript::class, wholeClasspath = true)
    }

    ide {
        acceptedLocations(ScriptAcceptedLocation.Everywhere)
    }
})