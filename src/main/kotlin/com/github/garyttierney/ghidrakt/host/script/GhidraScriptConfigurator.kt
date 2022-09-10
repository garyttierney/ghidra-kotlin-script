package com.github.garyttierney.ghidrakt.host.script

import kotlinx.coroutines.runBlocking
import kotlin.script.experimental.api.*
import kotlin.script.experimental.dependencies.maven.MavenDependenciesResolver
import kotlin.script.experimental.dependencies.maven.impl.mavenCentral
import kotlin.script.experimental.dependencies.resolveFromAnnotations
import kotlin.script.experimental.jvm.updateClasspath

class GhidraScriptConfigurator : RefineScriptCompilationConfigurationHandler {
    override fun invoke(context: ScriptConfigurationRefinementContext): ResultWithDiagnostics<ScriptCompilationConfiguration> {
        val diagnostics = arrayListOf<ScriptDiagnostic>()
        val resolver = MavenDependenciesResolver()
        resolver.repos.add(mavenCentral)

        val annotations = context.collectedData?.get(ScriptCollectedData.foundAnnotations)?.takeIf { it.isNotEmpty() }
            ?: return context.compilationConfiguration.asSuccess()

        val resolveResult = try {
            runBlocking {
                resolver.resolveFromAnnotations(annotations)
            }
        } catch (e: Throwable) {
            ResultWithDiagnostics.Failure(
                *diagnostics.toTypedArray(),
                e.asDiagnostics(path = context.script.locationId)
            )
        }

        return resolveResult.onSuccess { resolvedClassPath ->
            ScriptCompilationConfiguration(context.compilationConfiguration) {
                updateClasspath(resolvedClassPath)
            }.asSuccess()
        }
    }
}