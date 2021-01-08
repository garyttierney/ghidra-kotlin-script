package com.github.garyttierney.ghidrakt.api

import kotlin.script.experimental.annotations.KotlinScript

const val GHIDRA_KOTLIN_SCRIPT_EXTENSION = "ghidra.kts"

@KotlinScript(fileExtension = GHIDRA_KOTLIN_SCRIPT_EXTENSION, compilationConfiguration = GhidraKotlinScriptCompileConfiguration::class)
open class GhidraKotlinScript