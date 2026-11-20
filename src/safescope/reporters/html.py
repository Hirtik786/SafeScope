"""Self-contained HTML report (no external CSS/JS, safe to email or attach)."""

from __future__ import annotations

from html import escape

from safescope.models import Finding, ScanResult, Severity, Status

GRADE_COLOR = {"A": "#1f9d55", "B": "#5a9e1f", "C": "#d69e2e", "D": "#dd6b20", "F": "#c53030"}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a202c;--muted:#64748b;--line:#e2e8f0;
--pass:#1f9d55;--fail:#c53030;--warn:#b7791f;--info:#3567c6;--error:#8b3fb8;
--critical:#7b1fa2;--high:#c53030;--medium:#d97706;--low:#0e7490}
@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#171e27;--ink:#e6edf3;
--muted:#8b98a8;--line:#273241}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px 60px}
header{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin-bottom:24px}
.grade{width:96px;height:96px;border-radius:50%;display:grid;place-items:center;
color:#fff;font-size:38px;font-weight:800;flex:none}
h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--muted);font-size:13px}
.meta code{color:var(--ink)}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:0 0 24px}
.count{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;text-align:center}
.count b{display:block;font-size:24px}
.count span{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.toolbar{display:flex;gap:8px;margin:0 0 16px;flex-wrap:wrap}
.toolbar button{border:1px solid var(--line);background:var(--card);color:var(--ink);
border-radius:999px;padding:6px 14px;cursor:pointer;font:inherit;font-size:13px}
.toolbar button[aria-pressed=true]{background:var(--ink);color:var(--bg)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:0 0 16px;overflow:hidden}
section h2{font-size:15px;margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}
section h2 small{color:var(--muted);font-weight:400;margin-left:8px}
details{border-bottom:1px solid var(--line)}
details:last-child{border-bottom:0}
summary{list-style:none;display:flex;gap:10px;align-items:center;padding:10px 16px;cursor:pointer}
summary::-webkit-details-marker{display:none}
.badge{font-size:11px;font-weight:700;border-radius:6px;padding:2px 8px;color:#fff;flex:none;
text-transform:uppercase;letter-spacing:.04em}
.st-pass{background:var(--pass)}.st-fail{background:var(--fail)}.st-warn{background:var(--warn)}
.st-info{background:var(--info)}.st-error{background:var(--error)}
.sev{margin-left:auto;font-size:12px;font-weight:600;flex:none}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}
.sev-low{color:var(--low)}
.body{padding:0 16px 14px 16px;color:var(--ink)}
.body p{margin:6px 0}
.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;
white-space:pre-wrap;word-break:break-word;font-size:12.5px;margin:4px 0}
a{color:var(--info)}
footer{color:var(--muted);font-size:12px;margin-top:28px;text-align:center}
"""

JS = """
document.querySelectorAll('.toolbar button').forEach(function(b){
  b.addEventListener('click',function(){
    document.querySelectorAll('.toolbar button').forEach(function(x){x.setAttribute('aria-pressed','false')});
    b.setAttribute('aria-pressed','true');
    var f=b.dataset.filter;
    document.querySelectorAll('details[data-status]').forEach(function(d){
      d.hidden = f==='problems' ? !(d.dataset.status==='fail'||d.dataset.status==='warn') :
                 f==='all' ? false : d.dataset.status!==f;
    });
    document.querySelectorAll('section').forEach(function(s){
      s.hidden = !s.querySelector('details:not([hidden])');
    });
  });
});
"""


def _finding_html(f: Finding) -> str:
    st = f.status.value
    parts = [
        f'<details data-status="{st}"{" open" if f.is_problem and f.severity >= Severity.HIGH else ""}>',
        "<summary>",
        f'<span class="badge st-{st}">{escape(st)}</span>',
        f"<span>{escape(f.title)}</span>",
    ]
    if f.is_problem and f.severity > Severity.INFO:
        parts.append(f'<span class="sev sev-{f.severity.label}">{f.severity.label}</span>')
    parts.append("</summary><div class=body>")
    if f.description:
        parts.append(f"<p>{escape(f.description)}</p>")
    if f.evidence:
        parts.append(f'<div class=label>Evidence</div><pre>{escape(f.evidence)}</pre>')
    if f.recommendation and f.is_problem:
        parts.append(f'<div class=label>How to fix</div><pre>{escape(f.recommendation)}</pre>')
    if f.references:
        links = " · ".join(
            f'<a href="{escape(r, quote=True)}" rel="noopener noreferrer" target="_blank">{escape(r)}</a>'
            for r in f.references
        )
        parts.append(f"<p class=meta>{links}</p>")
    parts.append(f'<p class=meta>ID: <code>{escape(f.id)}</code></p></div></details>')
    return "".join(parts)


def render_html(result: ScanResult) -> str:
    color = GRADE_COLOR[result.grade[0]]
    sections: dict[str, list[Finding]] = {}
    for f in result.findings:
        sections.setdefault(f.check_id, []).append(f)

    body = []
    for check_id, findings in sections.items():
        problems = sum(1 for f in findings if f.is_problem)
        findings = sorted(findings, key=lambda f: (not f.is_problem, -f.severity))
        body.append(
            f"<section><h2>{escape(check_id.title())}"
            f"<small>{problems} issue{'s' if problems != 1 else ''}</small></h2>"
            + "".join(_finding_html(f) for f in findings)
            + "</section>"
        )

    counts = "".join(
        f'<div class=count><b class="sev-{name}">{n}</b><span>{name}</span></div>'
        for name, n in result.counts().items()
    )
    landed = (
        f" → <code>{escape(result.final_url)}</code>"
        if result.final_url and result.final_url != result.target
        else ""
    )
    statuses = {f.status for f in result.findings}
    filters = [("problems", "Issues"), ("all", "All")] + [
        (s.value, s.value.title()) for s in Status if s in statuses
    ]
    toolbar = "".join(
        f'<button type=button data-filter="{key}" aria-pressed="{"true" if key == "all" else "false"}">'
        f"{label}</button>"
        for key, label in filters
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeScope report – {escape(result.target)}</title>
<style>{CSS}</style>
</head>
<body><div class=wrap>
<header>
  <div class=grade style="background:{color}">{escape(result.grade)}</div>
  <div>
    <h1>SafeScope security report</h1>
    <div class=meta><code>{escape(result.target)}</code>{landed}</div>
    <div class=meta>Score {result.score}/100 · {escape(result.started_at)} ·
      {result.duration_seconds:.1f}s · SafeScope v{escape(result.tool_version)}</div>
  </div>
</header>
<div class=counts>{counts}</div>
<div class=toolbar>{toolbar}</div>
{''.join(body)}
<footer>Generated by SafeScope — passive, non-intrusive checks only.
Scan only systems you own or are authorised to test.</footer>
</div><script>{JS}</script></body></html>
"""
