package com.github.garyttierney.ghidrakt.plugin

import com.github.garyttierney.ghidrakt.KotlinScriptAPI
import ghidra.MiscellaneousPluginPackage
import ghidra.app.ExamplesPluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.INTERPRETERS,
    shortDescription = "Kotlin Script REPL",
    description = "Interactive Kotlin scripting console",
    servicesProvided = [KotlinScriptReplService::class]
)
class KotlinScriptReplPlugin(tool: PluginTool) : ProgramPlugin(tool, true, true), KotlinScriptAPI {
    val repl = KotlinScriptReplServiceImpl(this)

    init {
        registerServiceProvided(KotlinScriptReplService::class.java, repl)
    }

    override fun init() {
        repl.start()

        val provider = KotlinScriptReplProvider(this)
        provider.addToTool()
    }

    override fun dispose() {
        repl.stop()
    }

    override var currentLocation: ProgramLocation by this::currentLocation
    override var currentSelection: ProgramSelection by this::currentSelection
    override var currentHighlight: ProgramSelection by this::currentHighlight
    override var currentFunction: Function by this::currentFunction
    override val program: Program by this::currentProgram
}