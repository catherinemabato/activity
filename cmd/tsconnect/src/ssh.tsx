// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { useState, useCallback } from "preact/hooks"
import { Terminal } from "xterm"
import { FitAddon } from "xterm-addon-fit"

type SSHSessionDef = {
  username: string
  hostname: string
}

export function SSH({ netMap, ipn }: { netMap: IPNNetMap; ipn: IPN }) {
  const [sshSessionDef, setSSHSessionDef] = useState<SSHSessionDef | null>(null)
  const clearSSHSessionDef = useCallback(() => setSSHSessionDef(null), [])
  if (sshSessionDef) {
    return (
      <SSHSession def={sshSessionDef} ipn={ipn} onDone={clearSSHSessionDef} />
    )
  }
  const sshPeers = netMap.peers.filter(
    (p) => p.tailscaleSSHEnabled && p.online !== false
  )

  if (sshPeers.length == 0) {
    return <NoSSHPeers />
  }

  return <SSHForm sshPeers={sshPeers} onSubmit={setSSHSessionDef} />
}

function SSHSession({
  def,
  ipn,
  onDone,
}: {
  def: SSHSessionDef
  ipn: IPN
  onDone: () => void
}) {
  return (
    <div
      class="flex-grow bg-black p-2 overflow-hidden"
      ref={(node) => {
        if (node) {
          // Run the SSH session aysnchronously, so that the React render
          // loop is complete (otherwise the SSH form may still be visible,
          // which affects the size of the terminal, leading to a spurious
          // initial resize).
          setTimeout(() => runSSHSession(node, def, ipn, onDone), 0)
        }
      }}
    />
  )
}

function runSSHSession(
  termContainerNode: HTMLDivElement,
  def: SSHSessionDef,
  ipn: IPN,
  onDone: () => void
) {
  const term = new Terminal({
    cursorBlink: true,
  })
  const fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(termContainerNode)
  fitAddon.fit()

  let onDataHook: ((data: string) => void) | undefined
  term.onData((e) => {
    onDataHook?.(e)
  })

  term.focus()

  const sshSession = ipn.ssh(def.hostname, def.username, {
    writeFn: (input) => term.write(input),
    setReadFn: (hook) => (onDataHook = hook),
    rows: term.rows,
    cols: term.cols,
    onDone: () => {
      resizeObserver.disconnect()
      term.dispose()
      window.removeEventListener("beforeunload", handleBeforeUnload)
      onDone()
    },
  })

  // Make terminal and SSH session track the size of the containing DOM node.
  const resizeObserver = new ResizeObserver(() => fitAddon.fit())
  resizeObserver.observe(termContainerNode)
  term.onResize(({ rows, cols }) => sshSession.resize(rows, cols))

  // Close the session if the user closes the window without an explicit
  // exit.
  const handleBeforeUnload = () => sshSession.close()
  window.addEventListener("beforeunload", handleBeforeUnload)
}

function NoSSHPeers() {
  return (
    <div class="container mx-auto px-4 text-center">
      None of your machines have
      <a href="https://tailscale.com/kb/1193/tailscale-ssh/" class="link">
        Tailscale SSH
      </a>
      enabled. Give it a try!
    </div>
  )
}

function SSHForm({
  sshPeers,
  onSubmit,
}: {
  sshPeers: IPNNetMapPeerNode[]
  onSubmit: (def: SSHSessionDef) => void
}) {
  sshPeers = sshPeers.slice().sort((a, b) => a.name.localeCompare(b.name))
  const [username, setUsername] = useState("")
  const [hostname, setHostname] = useState(sshPeers[0].name)
  return (
    <form
      class="container mx-auto px-4 flex justify-center"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit({ username, hostname })
      }}
    >
      <input
        type="text"
        class="input username"
        placeholder="Username"
        onChange={(e) => setUsername(e.currentTarget.value)}
      />
      <div class="select-with-arrow mx-2">
        <select
          class="select"
          onChange={(e) => setHostname(e.currentTarget.value)}
        >
          {sshPeers.map((p) => (
            <option key={p.nodeKey}>{p.name.split(".")[0]}</option>
          ))}
        </select>
      </div>
      <input
        type="submit"
        class="button bg-green-500 border-green-500 text-white hover:bg-green-600 hover:border-green-600"
        value="SSH"
      />
    </form>
  )
}
