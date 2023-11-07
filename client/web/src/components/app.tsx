import cx from "classnames"
import React, { useEffect } from "react"
import LegacyClientView from "src/components/views/legacy-client-view"
import LoginClientView from "src/components/views/login-client-view"
import ManagementClientView from "src/components/views/management-client-view"
import ReadonlyClientView from "src/components/views/readonly-client-view"
import useAuth, { AuthResponse } from "src/hooks/auth"
import useNodeData, { NodeData, NodeUpdate, UpdateProgress, UpdateState } from "src/hooks/node-data"
import { ReactComponent as TailscaleIcon } from "src/icons/tailscale-icon.svg"
import ProfilePic from "src/ui/profile-pic"
import { Link, Route, Switch, useLocation } from "wouter"
import DeviceDetailsView from "./views/device-details-view"
import { apiFetch } from "src/api"
import { useState } from "react"
import { UpdatingView } from "./views/updating-view"
import { UpdateAvailableNotification } from "src/ui/update-available"

export default function App() {
  const { data: auth, loading: loadingAuth, newSession } = useAuth()
  const { data, refreshData, updateNode } = useNodeData()
  useEffect(() => {
    refreshData()
  }, [auth, refreshData])

  const initialUpdateState =
    (data?.ClientVersion.RunningLatest) ? UpdateState.UpToDate : UpdateState.Available

  const [updating, setUpdating] = useState<UpdateState>(initialUpdateState)

  const [updateLog, setUpdateLog] = useState<string>('')

  const appendUpdateLog = (msg: string) => {
    console.log(msg)
    setUpdateLog(updateLog + msg + '\n')
  }

  return (
    <main className="min-w-sm max-w-lg mx-auto py-14 px-5">
      {loadingAuth || !data ? (
        <div className="text-center py-14">Loading...</div> // TODO(sonia): add a loading view
      ) : (
        <>
          {/* TODO(sonia): get rid of the conditions here once full/readonly
           * views live on same components */}
          {data.DebugMode === "full" && auth?.ok && <Header node={data} />}
          <Switch>
            <Route path="/">
              <HomeView
                auth={auth}
                data={data}
                newSession={newSession}
                refreshData={refreshData}
                updateNode={updateNode}
                updating={updating}
                updateLog={updateLog}
                setUpdating={setUpdating}
                appendUpdateLog={appendUpdateLog}
              />
            </Route>
            {data.DebugMode !== "" && (
              <>
                <Route path="/details">
                  <DeviceDetailsView node={data} />
                </Route>
                <Route path="/subnets">{/* TODO */}Subnet router</Route>
                <Route path="/ssh">{/* TODO */}Tailscale SSH server</Route>
                <Route path="/serve">{/* TODO */}Share local content</Route>
              </>
            )}
            <Route>
              <h2 className="mt-8">Page not found</h2>
            </Route>
          </Switch>
        </>
      )}
    </main>
  )
}

function HomeView({
  auth,
  data,
  newSession,
  refreshData,
  updateNode,
  updating,
  updateLog,
  setUpdating,
  appendUpdateLog,
}: {
  auth?: AuthResponse
  data: NodeData
  newSession: () => Promise<void>
  refreshData: () => Promise<void>
  updateNode: (update: NodeUpdate) => Promise<void> | undefined
  updating: UpdateState
  updateLog: string,
  setUpdating: (u: UpdateState) => void,
  appendUpdateLog: (msg: string) => void,
}) {
  const updatingViewStates = [
    UpdateState.InProgress, UpdateState.Complete, UpdateState.Failed
  ]

  return (
    <>
      {data?.Status === "NeedsLogin" || data?.Status === "NoState" ? (
        // Client not on a tailnet, render login.
        <LoginClientView
          data={data}
          onLoginClick={() => updateNode({ Reauthenticate: true })}
        />
      ) : updatingViewStates.includes(updating) ? (
        <UpdatingView
          state={updating}
          cv={data.ClientVersion}
          updateLog={updateLog}
        />
      ) : data.DebugMode === "full" && auth?.ok ? (
        // Render new client interface in management mode.
        <>
        <ManagementClientView node={data} updateNode={updateNode} />
        {
          // TODO(naman): move into ReadonlyClient or ManagementClient
          data.ClientVersion.RunningLatest ? null : (
            <UpdateAvailableNotification
              currentVersion={data.IPNVersion}
              details={data.ClientVersion}
              updating={updating}
              setUpdating={setUpdating}
              appendUpdateLog={appendUpdateLog}
            />
          )
        }
      </>
      ) : data.DebugMode === "login" || data.DebugMode === "full" ? (
        // Render new client interface in readonly mode.
        <ReadonlyClientView data={data} auth={auth} newSession={newSession} />
      ) : (
        // Render legacy client interface.
        <LegacyClientView
          data={data}
          refreshData={refreshData}
          updateNode={updateNode}
        />
      )}
      {<Footer licensesURL={data.LicensesURL} />}
    </>
  )
}

function Header({ node }: { node: NodeData }) {
  const [loc] = useLocation()

  return (
    <>
      <div className="flex justify-between mb-12">
        <TailscaleIcon />
        <div className="flex">
          <p className="mr-2">{node.Profile.LoginName}</p>
          <ProfilePic url={node.Profile.ProfilePicURL} />
        </div>
      </div>
      {loc !== "/" && (
        <Link
          to="/"
          className="text-indigo-500 font-medium leading-snug block mb-[10px]"
        >
          &larr; Back to {node.DeviceName}
        </Link>
      )}
    </>
  )
}

export function Footer({
  licensesURL,
  className,
}: {
  licensesURL: string
  className?: string
}) {
  return (
    <footer className={cx("container max-w-lg mx-auto text-center", className)}>
      <a
        className="text-xs text-gray-500 hover:text-gray-600"
        href={licensesURL}
      >
        Open Source Licenses
      </a>
    </footer>
  )
}
