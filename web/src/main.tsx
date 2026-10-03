import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { applyMode, applyTheme, getStoredMode, getStoredTheme } from './theme'

// Applied before the first render (not inside a component) so there's no
// flash of the default palette/mode on a reload when the user has picked
// different ones -- see theme.ts.
applyTheme(getStoredTheme())
applyMode(getStoredMode())

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
