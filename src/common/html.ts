import QRCode from 'qrcode'

export const esc = (s: unknown) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

export const page = (title: string, body: string, opts: { refresh?: number } = {}) => `<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
${opts.refresh ? `<meta http-equiv="refresh" content="${opts.refresh}">` : ''}
<title>${esc(title)}</title>
<style>
  :root { --c:#155e86; --bg:#f6f8fa; --fg:#1f2328; --mut:#57606a; --ok:#1a7f37; --ng:#cf222e; }
  body { font-family: system-ui, -apple-system, "Hiragino Sans", "Noto Sans JP", sans-serif; margin:0; background:var(--bg); color:var(--fg); }
  header { background:var(--c); color:#fff; padding:12px 20px; }
  header h1 { margin:0; font-size:20px; }
  main { max-width: 960px; margin: 0 auto; padding: 16px 20px; }
  section { background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:12px 16px; margin:12px 0; }
  code, pre { background:#eff1f3; border-radius:4px; padding:2px 4px; font-size: 12px; }
  pre { padding:8px; overflow-x:auto; white-space: pre-wrap; word-break: break-all; }
  table { border-collapse: collapse; width:100%; font-size: 14px; }
  td, th { border-bottom:1px solid #d0d7de; padding:6px; text-align:left; vertical-align: top; }
  button, .btn { background:var(--c); color:#fff; border:0; border-radius:6px; padding:8px 14px; cursor:pointer; font-size:14px; text-decoration:none; display:inline-block; }
  .ok { color:var(--ok); font-weight:bold; } .ng { color:var(--ng); font-weight:bold; }
  .mut { color:var(--mut); font-size: 13px; }
  input { padding:6px; font-size:14px; }
</style></head>
<body><header><h1>${esc(title)}</h1></header><main>${body}</main></body></html>`

export const qrSvg = async (text: string) =>
  QRCode.toString(text, { type: 'svg', margin: 1, width: 260, errorCorrectionLevel: 'L' })

export const trustChainHtml = (path: string[]) =>
  path.map((p) => `<code>${esc(p)}</code>`).join(' &rarr; ')
