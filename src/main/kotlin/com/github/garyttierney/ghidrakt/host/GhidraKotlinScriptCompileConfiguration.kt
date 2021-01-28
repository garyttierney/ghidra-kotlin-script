package com.github.garyttierney.ghidrakt.host

import com.github.garyttierney.ghidrakt.KotlinScript
import com.github.garyttierney.ghidrakt.api.GhidraKotlinScript
import kotlin.script.experimental.api.*
import kotlin.script.experimental.dependencies.DependsOn
import kotlin.script.experimental.dependencies.Repository
import kotlin.script.experimental.jvm.dependenciesFromClassContext
import kotlin.script.experimental.jvm.jvm

class GhidraKotlinScriptCompileConfiguration : ScriptCompilationConfiguration({
    implicitReceivers(KotlinScript::class)

    defaultImports(DependsOn::class, Repository::class)
    
    refineConfiguration {
        onAnnotations(DependsOn::class, Repository::class, handler = GhidraKotlinScriptConfigurator())
    }

    jvm {
        dependenciesFromClassContext(GhidraKotlinScript::class, wholeClasspath = true)
    }

    ide {
        acceptedLocations(ScriptAcceptedLocation.Everywhere)
    }
})