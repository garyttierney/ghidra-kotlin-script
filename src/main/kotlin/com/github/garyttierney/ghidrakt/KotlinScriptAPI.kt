package com.github.garyttierney.ghidrakt

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.program.util.ProgramSelection

interface KotlinScriptAPI {
    var currentFunction: Function
    var currentHighlight: ProgramSelection
    var currentLocation: ProgramLocation
    var currentSelection: ProgramSelection
    val program: Program
}