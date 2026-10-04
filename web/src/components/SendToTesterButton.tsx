import { sendToTester } from '../testerHandoff'

// SendToTesterButton is the visible "Send to Tester" control every scanner's
// finding shows, styled like CopyButton. It hands over the finding's whole
// captured request -- method, URL, headers and body -- so the Tester opens
// ready to replay exactly what the scanner sent. Anything a scanner didn't
// capture is simply left out and the Tester falls back to its own default.
export function SendToTesterButton({
  url,
  method,
  headers,
  body,
}: {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string
}) {
  return (
    <button
      onClick={(e) => {
        // Findings render inside expandable rows, so keep this click from also toggling the row.
        e.stopPropagation()
        sendToTester(url, method || 'GET', headers, body)
      }}
      className="shrink-0 rounded border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-300 hover:border-sky-500 hover:text-sky-300"
    >
      Send to Tester
    </button>
  )
}
