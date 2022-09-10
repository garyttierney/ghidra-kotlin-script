package com.github.garyttierney.ghidrakt.api

import com.github.garyttierney.ghidrakt.host.script.GhidraScriptCompilationConfiguration
import kotlin.script.experimental.annotations.KotlinScript

const val GHIDRA_KOTLIN_SCRIPT_EXTENSION = "ghidra.kts"

@KotlinScript(
    fileExtension = GHIDRA_KOTLIN_SCRIPT_EXTENSION,
    compilationConfiguration = GhidraScriptCompilationConfiguration::class
)
open class GhidraKotlinScript