import { useEffect, useState } from 'react'

// Placeholder: shows which mode the registry API runs in.
function App() {
  const [mode, setMode] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/health')
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      })
      .then((health: { mode: string }) => setMode(health.mode))
      .catch((e: Error) => setError(e.message))
  }, [])

  if (error) return <p>Registry API unreachable: {error}</p>
  if (mode === null) return <p>Loading…</p>
  return (
    <main>
      <h1>Double Blind Eval Registry</h1>
      <p>Mode: {mode}</p>
    </main>
  )
}

export default App
