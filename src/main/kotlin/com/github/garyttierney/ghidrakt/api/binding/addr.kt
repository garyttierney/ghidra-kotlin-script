package com.github.garyttierney.ghidrakt.api.binding

import ghidra.program.model.address.Address

operator fun Address.minus(other: Address) = addressSpace.getAddress(subtract(other))
operator fun Address.plus(other: Address) = getNewAddress(other.offset)
