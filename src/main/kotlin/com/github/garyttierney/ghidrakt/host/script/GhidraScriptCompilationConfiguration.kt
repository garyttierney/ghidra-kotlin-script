package com.github.garyttierney.ghidrakt.host.script

import com.github.garyttierney.ghidrakt.KotlinScriptAPI
import com.github.garyttierney.ghidrakt.api.GhidraKotlinScript
import kotlin.script.experimental.api.*
import kotlin.script.experimental.dependencies.DependsOn
import kotlin.script.experimental.dependencies.Repository
import kotlin.script.experimental.jvm.dependenciesFromClassContext
import kotlin.script.experimental.jvm.jvm

class GhidraScriptCompilationConfiguration : ScriptCompilationConfiguration({
    implicitReceivers(KotlinScriptAPI::class)

    defaultImports("com.github.garyttierney.ghidrakt.api.binding.*")

    refineConfiguration {
        onAnnotations(DependsOn::class, Repository::class, handler = GhidraScriptConfigurator())
    }

    jvm {
        dependenciesFromClassContext(
            GhidraKotlinScript::class,
            wholeClasspath = true,
            libraries = arrayOf("kotlin-stdlib", "kotlin-reflect")
        )
    }

    ide {
        acceptedLocations(ScriptAcceptedLocation.Everywhere)
    }
})