package com.github.garyttierney.ghidrakt.plugin

import com.github.garyttierney.ghidrakt.plugin.shell.tty.StreamTtyConnector
import com.jediterm.terminal.ui.JediTermWidget
import com.jediterm.terminal.ui.settings.DefaultSettingsProvider
import ghidra.framework.plugintool.ComponentProviderAdapter
import java.awt.Dimension
import java.awt.event.KeyEvent
import java.awt.event.KeyListener
import javax.swing.JComponent

// Ghidra checks if shortcuts should fire by checking if a key listener consumes inputs,
// a component that only consumes inputs in input mode without a key listener will not
// be passed inputs that activate shortcuts.
val consumeAllKeyListener = object : KeyListener {
    override fun keyTyped(e: KeyEvent) = e.consume()
    override fun keyPressed(e: KeyEvent) = e.consume()
    override fun keyReleased(e: KeyEvent) = e.consume()
}

class KotlinScriptReplProvider(private val plugin: KotlinScriptReplPlugin) :
    ComponentProviderAdapter(plugin.tool, "REPL", plugin.name) {

    private val defaultSettingsProvider = object : DefaultSettingsProvider() {
        override fun maxRefreshRate() = 144
    }

    private val term = createTerminalWidget()

    private fun createTerminalWidget() = JediTermWidget(Dimension(120, 100), defaultSettingsProvider).apply {
        ttyConnector = StreamTtyConnector(plugin.repl.terminalOutputSource, plugin.repl.terminalInputSink)
        terminalPanel.addKeyListener(consumeAllKeyListener)

        start()
    }

    override fun getComponent(): JComponent {
        return term
    }
}