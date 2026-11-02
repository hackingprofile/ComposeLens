// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"composelens/internal/safety"
)

const (
	htmlDoctype = "<!DOCTYPE html>"
	dataID      = "composelens-report-data"
)

// HTML wraps a validated composelens.report.v0 JSON document in a single
// self-contained offline file. Untrusted values live in a JSON data island
// (HTML-escaped so </script> cannot break out) and are painted with
// textContent only. Four keyboard-navigable views share that island.
// CSP hashes pin the controller script, JSON island, and CSS so the report
// can run under default-src 'none' without unsafe-inline.
func HTML(pkgJSON []byte) ([]byte, error) {
	if err := ValidateBytes(pkgJSON); err != nil {
		return nil, err
	}
	var escaped bytes.Buffer
	json.HTMLEscape(&escaped, bytes.TrimSpace(pkgJSON))
	island := escaped.Bytes()
	csp := cspPolicy(cspSHA256([]byte(htmlCSS)), cspSHA256([]byte(htmlBoot)), cspSHA256(island))
	var b strings.Builder
	b.WriteString(htmlDoctype)
	b.WriteByte('\n')
	b.WriteString(htmlHeadPreCSP)
	b.WriteString(csp)
	b.WriteString(htmlHeadPostCSP)
	b.WriteString(htmlCSS)
	b.WriteString(htmlPrefix)
	b.WriteString(dataID)
	b.WriteString(`">`)
	b.Write(island)
	b.WriteString("</script>\n<script>")
	b.WriteString(htmlBoot)
	b.WriteString("</script>\n</body></html>\n")
	out := []byte(b.String())
	if len(out) > MaxHTMLBytes {
		return nil, safety.NewParseError(safety.CodeTotalTooLarge, "report.html", fmt.Sprintf("rendered HTML exceeds %d bytes", MaxHTMLBytes))
	}
	if refs := RemoteRefs(out); len(refs) > 0 {
		return nil, fmt.Errorf("report html: remote refs: %s", strings.Join(refs, ", "))
	}
	if sinks := LiveSinks(out); len(sinks) > 0 {
		return nil, fmt.Errorf("report html: live sinks: %s", strings.Join(sinks, ", "))
	}
	return out, nil
}

const htmlCSS = `*{box-sizing:border-box}
body{margin:0;color:` + ColorText + `;background:` + ColorBg + `;font-family:system-ui,"Segoe UI","Segoe UI Variable Text",sans-serif;font-size:1rem;line-height:1.55}
.app-bar-in,.chips,.overview,main,noscript{max-width:76rem;margin-left:auto;margin-right:auto;padding-left:1.4rem;padding-right:1.4rem}
.app-bar{background:` + ColorBand + `}
.app-bar-in{display:flex;justify-content:space-between;align-items:flex-start;gap:1.2rem;flex-wrap:wrap;padding-top:1.75rem;padding-bottom:1.6rem}
.app-id{min-width:0;flex:1 1 18rem}
.brand{margin:0 0 .42rem;font-size:.71rem;font-weight:650;letter-spacing:.17em;text-transform:uppercase;color:` + ColorBandEyebrow + `}
h1{font-family:Georgia,"Iowan Old Style","Palatino Linotype","Times New Roman",ui-serif,serif;font-size:2rem;font-weight:700;letter-spacing:-.006em;line-height:1.1;margin:0 0 .45rem;color:` + ColorCard + `}
h2{font-family:Georgia,"Iowan Old Style","Palatino Linotype","Times New Roman",ui-serif,serif;font-size:1.3rem;font-weight:700;letter-spacing:-.004em;margin:0 0 .95rem;color:` + ColorBrand + `}
h3.list-title{font-size:.71rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:` + ColorNote + `;margin:0 0 .7rem}
.lede{margin:0;max-width:44rem;color:` + ColorBandLede + `;font-size:.98rem;line-height:1.5}
.badge-ver{margin:0;background:` + ColorCard + `;color:` + ColorBand + `;padding:.32rem .74rem;border-radius:.5rem;font-size:.82rem;font-weight:700;letter-spacing:.01em;align-self:flex-start;box-shadow:0 4px 12px -2px rgba(3,12,34,.45)}
.chips{display:flex;flex-wrap:wrap;gap:.45rem;margin:1.15rem auto .1rem}
.chip{background:` + ColorChipBg + `;color:` + ColorText + `;border:1px solid ` + ColorUIBorder + `;border-radius:999px;padding:.2rem .72rem;font-size:.77rem;font-weight:500}
.overview,.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));gap:.75rem}
.overview{margin:1.05rem auto 1.4rem}
.tile{background:` + ColorCard + `;border:1px solid ` + ColorUIBorder + `;border-radius:.75rem;padding:1rem 1.05rem;box-shadow:0 1px 2px rgba(13,42,84,.06),0 14px 30px -14px rgba(13,42,84,.28)}
.tile-n{font-size:1.75rem;font-weight:700;letter-spacing:-.03em;color:` + ColorBrand + `;line-height:1.05;font-variant-numeric:tabular-nums}
.tile-l{margin-top:.34rem;font-size:.7rem;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:` + ColorNote + `}
.note{color:` + ColorNote + `;font-size:.9rem;margin:.2rem 0 .75rem}
:focus,:focus-visible{outline:3px solid ` + ColorFocus + `;outline-offset:2px;border-radius:.25rem}
[hidden]{display:none}
[role=tablist]{display:flex;flex-wrap:nowrap;overflow-x:auto;gap:.2rem;margin:.35rem 0 1.2rem;padding:0;border-bottom:2px solid ` + ColorUIBorder + `;background:transparent}
[role=tab]{flex:0 0 auto;font:inherit;font-weight:600;padding:.68rem 1.25rem;border:none;border-radius:.55rem .55rem 0 0;background:transparent;color:` + ColorNote + `}
[role=tab][aria-selected=true]{background:` + ColorCard + `;color:` + ColorBrand + `;box-shadow:inset 0 -3px 0 ` + ColorBrand + `,0 -6px 16px -10px rgba(13,42,84,.3)}
.panel{margin:0 0 1.3rem}
.card{background:` + ColorCard + `;border:1px solid ` + ColorUIBorder + `;border-radius:.85rem;padding:1.1rem 1.2rem;box-shadow:0 1px 2px rgba(13,42,84,.06),0 16px 34px -16px rgba(13,42,84,.3)}
.view-body{display:grid;grid-template-columns:minmax(0,1.12fr) minmax(0,.88fr);gap:1.1rem;align-items:start}
.view-stack{display:grid;gap:1.1rem}
[role=listbox]{border:none;border-radius:0;background:transparent;padding:0;min-height:2rem}
[role=option]{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem .55rem;width:100%;font:inherit;text-align:left;margin:.4rem 0;padding:.62rem .75rem;border:1px solid ` + ColorUIBorder + `;border-radius:.5rem;background:` + ColorCard + `;color:` + ColorText + `;box-shadow:0 1px 2px rgba(13,42,84,.05)}
[role=option][aria-selected=true]{border-color:` + ColorFocus + `;box-shadow:inset 3px 0 0 ` + ColorFocus + `,0 3px 12px -3px rgba(29,78,216,.3)}
.row-id{flex:1 1 11rem;font-weight:650;min-width:0;overflow-wrap:anywhere;font-family:ui-monospace,"Cascadia Code","Consolas","SFMono-Regular",monospace;font-size:.9rem}
.row-extra{flex:1 1 100%;color:` + ColorNote + `;font-size:.87rem;font-weight:400}
.badge{display:inline-flex;align-items:center;padding:.14rem .5rem;border-radius:.35rem;font-size:.67rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;border:1px solid transparent}
.badge-type{background:` + ColorTabBg + `;color:` + ColorText + `;border-color:` + ColorUIBorder + `}
.st-ok{background:` + ColorOkBg + `;color:` + ColorOkFg + `}
.st-warn{background:` + ColorAmberBg + `;color:` + ColorWarn + `}
.st-err{background:` + ColorErrBg + `;color:` + ColorError + `}
.st-note{background:` + ColorTabBg + `;color:` + ColorNote + `}
.detail{margin-top:0}
.kv{display:grid;grid-template-columns:8rem minmax(0,1fr);gap:.4rem .8rem;margin:.42rem 0;align-items:start}
.kv-k{color:` + ColorNote + `;font-size:.68rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding-top:.12rem}
.kv-v{color:` + ColorText + `;overflow-wrap:anywhere;font-family:ui-monospace,"Cascadia Code","Consolas","SFMono-Regular",monospace;font-size:.9rem}
.chain{margin:.6rem 0 0;padding:0;list-style:none}
.chain li{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem .55rem;margin:.35rem 0;padding:.52rem .62rem;border:1px solid ` + ColorUIBorder + `;border-radius:.5rem;background:` + ColorBg + `}
.winner{font-weight:700}
.shadowed{color:` + ColorNote + `}
.item{margin:.3rem 0;color:` + ColorNote + `;font-size:.9rem}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip:focus{position:static;width:auto;height:auto;margin:.9rem auto 0;padding:.5rem .75rem;clip:auto;overflow:visible;color:` + ColorText + `;background:` + ColorCard + `;outline:3px solid ` + ColorFocus + `;outline-offset:2px;max-width:76rem;border-radius:.4rem}
@media (max-width:48rem){.app-bar-in,.chips,.overview,main,noscript{padding-left:1.1rem;padding-right:1.1rem}h1{font-size:1.65rem}h2{font-size:1.18rem}.view-body{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
@media (prefers-reduced-motion: reduce){*,*::before,*::after{animation:none !important;transition:none !important;scroll-behavior:auto !important}}
`

const htmlHeadPreCSP = `<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="`

const htmlHeadPostCSP = `">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ComposeLens report</title>
<style>`

const htmlPrefix = `</style>
</head>
<body>
<a class="skip" id="skip-to-content" href="#main">Skip to report views</a>
<header class="app-bar">
<div class="app-bar-in">
<div class="app-id">
<p class="brand">ComposeLens</p>
<h1>ComposeLens report</h1>
<p class="lede">Offline source inspection — provenance, engine differential, and diagnostics.</p>
</div>
<p id="ver-badge" class="badge-ver"></p>
</div>
</header>
<div id="chips" class="chips" aria-label="Report identity"></div>
<div id="overview" class="overview" aria-label="Report summary"></div>
<div id="live" class="sr-only" aria-live="polite" aria-atomic="true"></div>
<main id="main" tabindex="-1">
<nav id="view-tabs" role="tablist" aria-label="Report views">
<button type="button" role="tab" id="tab-graph" data-view="graph" aria-controls="view-graph" aria-selected="true" tabindex="0" aria-label="Graph, provenance and shadow-chains">Graph</button>
<button type="button" role="tab" id="tab-source" data-view="source" aria-controls="view-source" aria-selected="false" tabindex="-1" aria-label="Source, source chain">Source</button>
<button type="button" role="tab" id="tab-diff" data-view="diff" aria-controls="view-diff" aria-selected="false" tabindex="-1" aria-label="Diff, differential">Diff</button>
<button type="button" role="tab" id="tab-diagnostics" data-view="diagnostics" aria-controls="view-diagnostics" aria-selected="false" tabindex="-1" aria-label="Diagnostics">Diagnostics</button>
</nav>
<section id="view-graph" class="panel" role="tabpanel" data-view="graph" aria-labelledby="heading-graph tab-graph">
<h2 id="heading-graph">Provenance graph</h2>
<p id="graph-sr" class="sr-only"></p>
<div id="graph-tiles" class="tiles" aria-label="Graph counts"></div>
<div class="view-body">
<div class="card">
<h3 class="list-title">Nodes</h3>
<div id="graph-list" role="listbox" aria-label="Graph nodes" data-list="graph"></div>
</div>
<div id="graph-detail" class="card detail" hidden aria-label="Expanded shadow-chain"></div>
</div>
</section>
<section id="view-source" class="panel" role="tabpanel" data-view="source" aria-labelledby="heading-source tab-source" hidden>
<h2 id="heading-source">Source chain</h2>
<p id="source-sr" class="sr-only"></p>
<div id="source-meta" class="card" aria-label="Source location"></div>
<div class="view-stack">
<div class="card">
<h3 class="list-title">Services</h3>
<div id="source-list" role="listbox" aria-label="Services" data-list="source"></div>
</div>
<div class="card">
<h3 class="list-title">Findings</h3>
<div id="findings-list" role="listbox" aria-label="Check findings" data-list="findings"></div>
</div>
<div class="card">
<h3 class="list-title">Targets</h3>
<div id="source-targets" role="listbox" aria-label="Graph targets" data-list="targets"></div>
</div>
<div id="source-detail" class="card detail" hidden aria-label="Selected source chain"></div>
</div>
</section>
<section id="view-diff" class="panel" role="tabpanel" data-view="diff" aria-labelledby="heading-diff tab-diff" hidden>
<h2 id="heading-diff">Diff / differential</h2>
<p id="diff-sr" class="sr-only"></p>
<div id="diff-tiles" class="tiles" aria-label="Diff counts"></div>
<div class="view-body">
<div class="card">
<h3 class="list-title">Rows</h3>
<div id="diff-list" role="listbox" aria-label="Differential rows" data-list="diff"></div>
</div>
<div id="diff-detail" class="card detail" hidden aria-label="Selected differential row"></div>
</div>
</section>
<section id="view-diagnostics" class="panel" role="tabpanel" data-view="diagnostics" aria-labelledby="heading-diagnostics tab-diagnostics" hidden>
<h2 id="heading-diagnostics">Diagnostics</h2>
<p id="diagnostics-sr" class="sr-only"></p>
<div class="view-body">
<div class="card">
<h3 class="list-title">Entries</h3>
<div id="diagnostics-list" role="listbox" aria-label="Diagnostic entries" data-list="diagnostics"></div>
</div>
<div id="diagnostics-detail" class="card detail" hidden aria-label="Selected diagnostic"></div>
</div>
</section>
</main>
<noscript><p class="note">Enable script in this local file to paint the four views. No network is used.</p></noscript>
<script type="application/json" id="`

// htmlBoot paints the four views. Trusted chrome only; package strings use textContent.
// keyboard: Enter Space ArrowLeft ArrowRight ArrowUp ArrowDown Escape
// no mouse-only path: click on buttons duplicates Enter/Space
const htmlBoot = `(function(){
var K={left:"ArrowLeft",right:"ArrowRight",up:"ArrowUp",down:"ArrowDown",home:"Home",end:"End",esc:"Escape",enter:"Enter",space:" "};
function el(tag){return document.createElement(tag);}
function txt(node, value){node.textContent = value == null ? "" : String(value);}
function p(parent, tag, value){var n=el(tag);txt(n,value);parent.appendChild(n);return n;}
function line(parent, value){p(parent,"div",value).className="item";}
function clear(node){while(node.firstChild){node.removeChild(node.firstChild);}}
function isActivate(e){return e.key===K.enter || e.key===K.space || e.key==="Spacebar";}
function announce(msg){
  var live=document.getElementById("live");
  if(!live){return;}
  txt(live, msg);
}
function setSR(id, msg){
  var n=document.getElementById(id);
  if(n){txt(n, msg);}
}
function badge(parent, text, cls){
  var s=el("span");
  s.className="badge "+(cls||"badge-type");
  txt(s, text);
  parent.appendChild(s);
  return s;
}
function statusClass(state){
  var s=(state||"").toLowerCase();
  if(s==="ok"||s==="match"||s==="resolved"||s==="present"){return "st-ok";}
  if(s==="only-engine"||s==="only-internal"||s==="warning"||s==="warn"||s==="uncertain"||s==="overridden"){return "st-warn";}
  if(s==="divergent"||s==="error"){return "st-err";}
  return "st-note";
}
function statusOf(row){
  if(row && row.classification){return row.classification;}
  return (row && row.state) || "";
}
function tile(parent, value, label){
  var t=el("div");
  t.className="tile";
  p(t,"div",String(value)).className="tile-n";
  p(t,"div",label).className="tile-l";
  parent.appendChild(t);
}
function chip(parent, text){
  var s=el("span");
  s.className="chip";
  txt(s, text);
  parent.appendChild(s);
}
function kv(parent, key, value){
  var row=el("div");
  row.className="kv";
  var k=el("span");
  k.className="kv-k";
  txt(k, key);
  var v=el("span");
  v.className="kv-v";
  txt(v, value==null?"":String(value));
  row.appendChild(k);
  row.appendChild(v);
  parent.appendChild(row);
}
function addRow(list, ident, kind, state, extra, activate){
  var b=el("button");
  b.type="button";
  b.setAttribute("role","option");
  b.setAttribute("aria-selected","false");
  b.tabIndex=-1;
  var idel=el("span");
  idel.className="row-id";
  txt(idel, ident||"");
  b.appendChild(idel);
  if(kind){badge(b, kind, "badge-type");}
  if(state){badge(b, state, statusClass(state));}
  if(extra){
    var x=el("span");
    x.className="row-extra";
    txt(x, extra);
    b.appendChild(x);
  }
  b.addEventListener("click", activate);
  list.appendChild(b);
  return b;
}
var data=document.getElementById("` + dataID + `");
var pkg=JSON.parse(data.textContent);
txt(document.getElementById("ver-badge"), pkg.version||"");
var chips=document.getElementById("chips");
if(pkg.schema){chip(chips, pkg.schema);}
if(pkg.determinism){chip(chips, pkg.determinism);}
chip(chips, "offline");
var graph=pkg.graph||{};
var nodes=graph.nodes||[];
var source=pkg.source||{};
var services=source.services||[];
var uniq=source.serviceSummary||services;
var check=pkg.check||{};
var findings=check.findings||[];
var diff=pkg.diff||{};
var dfr=pkg.differential||{};
var rows=dfr.rows||[];
var diags=pkg.diagnostics||[];
var expanded=null;
var gc=graph.counts||{};
var counts=check.counts||{};
var sum=dfr.summary||{};
var overview=document.getElementById("overview");
tile(overview, uniq.length, "Services");
tile(overview, counts.total||findings.length, "Findings");
tile(overview, sum.match||0, "Match");
tile(overview, diags.length, "Diagnostics");
function serviceNames(){
  var names=[], seen={}, i;
  function add(s){
    if(!s || seen[s]){return;}
    seen[s]=true;
    names.push(s);
  }
  for(i=0;i<services.length;i++){add((services[i]||{}).name);}
  for(i=0;i<nodes.length;i++){
    if((nodes[i].kind||"")==="service"){add(nodes[i].target||"");}
  }
  return names;
}
function mapServiceIdentity(target){
  var p="services.";
  if(!target || target.indexOf(p)!==0){return "";}
  var body=target.slice(p.length);
  if(!body){return "";}
  var names=serviceNames();
  var i;
  for(i=0;i<names.length;i++){
    if(body===names[i]){return names[i];}
  }
  return "";
}
function findNode(target, kind){
  var t=target||"";
  var k=kind||"";
  var i, hits=[];
  for(i=0;i<nodes.length;i++){
    if((nodes[i].target||"")!==t){continue;}
    if(k && (nodes[i].kind||"")!==k){continue;}
    hits.push(nodes[i]);
  }
  if(hits.length===1){return hits[0];}
  if(hits.length>1){return null;}
  if(k){return null;}
  var svc=mapServiceIdentity(t);
  if(svc){
    for(i=0;i<nodes.length;i++){
      if((nodes[i].target||"")===svc && (nodes[i].kind||"")==="service"){return nodes[i];}
    }
  }
  return null;
}
function fillChain(detail, node){
  clear(detail);
  if(!node){line(detail,"(no provenance node)");detail.removeAttribute("hidden");return;}
  kv(detail, "Identity", node.target||"");
  var flags=el("div");
  if(node.kind){badge(flags, node.kind, "badge-type");}
  if(node.state){badge(flags, node.state, statusClass(node.state));}
  if(flags.firstChild){detail.appendChild(flags);}
  if(node.effective!=null){kv(detail, "Effective", String(node.effective));}
  var chain=node.shadowChain||[];
  if(chain.length===0){line(detail,"(empty shadow-chain)");}
  var ol=el("ol");
  ol.className="chain";
  for(var i=0;i<chain.length;i++){
    var L=chain[i]||{};
    var li=el("li");
    var role=L.role||"";
    li.className=role==="winner"?"winner":(role==="shadowed"?"shadowed":"");
    if(L.order!=null){badge(li, String(L.order), "badge-type");}
    if(role){badge(li, role, role==="winner"?"st-ok":"st-note");}
    var idn=el("span");
    idn.className="row-id";
    txt(idn, L.source||L.stage||"");
    li.appendChild(idn);
    if(L.stage && L.source){badge(li, L.stage, "badge-type");}
    if(L.state){badge(li, L.state, statusClass(L.state));}
    ol.appendChild(li);
  }
  if(chain.length){detail.appendChild(ol);}
  detail.removeAttribute("hidden");
}
function hideDetail(id){
  var d=document.getElementById(id);
  clear(d);
  d.setAttribute("hidden","hidden");
}
function toggleGraph(node){
  var d=document.getElementById("graph-detail");
  var key=(node.kind||"")+"\t"+(node.target||"");
  if(expanded===key && !d.hasAttribute("hidden")){
    expanded=null;
    hideDetail("graph-detail");
    announce("Shadow-chain collapsed");
    return;
  }
  expanded=key;
  fillChain(d, node);
  announce("Shadow-chain expanded");
}
function showSourceFor(target, kind, ref){
  var node=ref?findNode(ref.target||"", ref.kind||""):findNode(target, kind);
  fillChain(document.getElementById("source-detail"), node);
  announce(node?"Source chain shown":"No source chain for this item");
}
function showDiff(row){
  var d=document.getElementById("diff-detail");
  clear(d);
  kv(d, "Path", row.path||"");
  var flags=el("div");
  if(row.kind){badge(flags, row.kind, "badge-type");}
  var st=statusOf(row);
  if(st){badge(flags, st, statusClass(st));}
  if(flags.firstChild){d.appendChild(flags);}
  if(row.internal){kv(d, "Internal", row.internal);}
  if(row.engine){kv(d, "Engine", row.engine);}
  if(row.detail){kv(d, "Detail", row.detail);}
  d.removeAttribute("hidden");
  announce("Differential row shown");
}
function showDiag(ent){
  var d=document.getElementById("diagnostics-detail");
  clear(d);
  kv(d, "Code", ent.code||"");
  kv(d, "Message", ent.message||"");
  if(ent.remediation){kv(d, "Remediation", ent.remediation);}
  var doc=el("p");
  doc.id="diag-doc";
  doc.tabIndex=-1;
  doc.setAttribute("aria-label","Documentation reference");
  txt(doc,"doc: "+(ent.doc||"(none)"));
  d.appendChild(doc);
  d.removeAttribute("hidden");
  doc.focus();
  announce("Documentation reference focused");
}
function armList(list){
  var opts=list.querySelectorAll("[role=option]");
  if(!opts.length){return;}
  opts[0].tabIndex=0;
  opts[0].setAttribute("aria-selected","true");
}
function markOpt(opts, i){
  for(var n=0;n<opts.length;n++){
    opts[n].tabIndex=-1;
    opts[n].setAttribute("aria-selected","false");
  }
  opts[i].tabIndex=0;
  opts[i].setAttribute("aria-selected","true");
  opts[i].focus();
  announce("Selected "+opts[i].textContent);
}
function setView(name){
  var tabs=document.querySelectorAll("[role=tab]");
  for(var i=0;i<tabs.length;i++){
    var on=tabs[i].getAttribute("data-view")===name;
    tabs[i].setAttribute("aria-selected", on?"true":"false");
    tabs[i].tabIndex=on?0:-1;
  }
  var panels=document.querySelectorAll("[role=tabpanel]");
  for(var j=0;j<panels.length;j++){
    if(panels[j].getAttribute("data-view")===name){panels[j].removeAttribute("hidden");}
    else{panels[j].setAttribute("hidden","hidden");}
  }
  var sr=document.getElementById(name+"-sr");
  if(sr && sr.textContent){announce(sr.textContent);}
}
function focusTab(i){
  var tabs=document.querySelectorAll("[role=tab]");
  if(!tabs.length){return;}
  if(i<0){i=tabs.length-1;}
  if(i>=tabs.length){i=0;}
  setView(tabs[i].getAttribute("data-view"));
  tabs[i].focus();
}
function backOut(from){
  var panel=from;
  while(panel && panel.getAttribute && panel.getAttribute("role")!=="tabpanel"){panel=panel.parentNode;}
  var viewName=panel && panel.getAttribute ? panel.getAttribute("data-view") : "graph";
  var detail=document.getElementById(viewName+"-detail");
  if(detail && !detail.hasAttribute("hidden")){
    hideDetail(viewName+"-detail");
    expanded=null;
    var list=document.getElementById(viewName==="source"?"source-list":viewName+"-list");
    if(from.id==="diag-doc"){list=document.getElementById("diagnostics-list");}
    var opt=list && list.querySelector("[role=option][tabindex=\"0\"]");
    if(opt){opt.focus();return;}
    if(from.focus){from.focus();}
    return;
  }
  var tab=document.getElementById("tab-"+viewName);
  if(tab){tab.focus();}
}
var shadowed=0;
for(var si=0;si<nodes.length;si++){
  var ch=(nodes[si]&&nodes[si].shadowChain)||[];
  for(var ci=0;ci<ch.length;ci++){
    if((ch[ci].role||"")==="shadowed"){shadowed++;}
  }
}
setSR("graph-sr", "Provenance graph: "+String(gc.total||nodes.length)+" nodes, "+String(gc.services||0)+" services, "+String(shadowed)+" shadowed");
var gt=document.getElementById("graph-tiles");
tile(gt, gc.total||nodes.length, "Nodes");
tile(gt, gc.fields||0, "Fields");
tile(gt, gc.env||0, "Env");
var glist=document.getElementById("graph-list");
var n;
for(n=0;n<nodes.length;n++){
  (function(node){
    addRow(glist, node.target||"", node.kind||"", node.state||"", "", function(){ toggleGraph(node); });
  })(nodes[n]||{});
}
if(nodes.length===0){line(glist,"(no nodes)");}
armList(glist);
setSR("source-sr", "Source chain: "+String(uniq.length)+" services, "+String(counts.total||findings.length)+" findings");
var smeta=document.getElementById("source-meta");
kv(smeta, "Project", source.projectDirectory||"");
kv(smeta, "Files", source.fileEvidence||"");
kv(smeta, "Gate", check.gate||"");
kv(smeta, "Assertion", String(check.assertionExit||0));
var slist=document.getElementById("source-list");
var s;
function declLabel(svc){
  var d=svc.declarations;
  if(!d){return svc.identity||"";}
  var proj=source.projectDirectory||"";
  var out=[], i;
  for(i=0;i<d.length;i++){
    var f=(d[i]||{}).file||"";
    if(proj && f.indexOf(proj)===0){f=f.slice(proj.length).replace(/^[\\\/]+/,"");}
    out.push(f+":"+String((d[i]||{}).line||0));
  }
  return "declared in "+out.join(", ");
}
for(s=0;s<uniq.length;s++){
  (function(svc){
    addRow(slist, svc.name||"", "service", "", declLabel(svc), function(){ showSourceFor(svc.name||mapServiceIdentity(svc.identity||"")||svc.identity||"", "service"); });
  })(uniq[s]||{});
}
if(uniq.length===0){line(slist,"(no services)");}
armList(slist);
var flist=document.getElementById("findings-list");
var fi;
for(fi=0;fi<findings.length;fi++){
  (function(fnd){
    var b=addRow(flist, fnd.target||"", fnd.kind||"finding", fnd.severity||"", fnd.message||"", function(){ showSourceFor(fnd.target||"", fnd.kind||"", fnd.graphNode||null); });
    if(fnd.id){
      var idchip=el("span");
      idchip.className="badge badge-type";
      txt(idchip, fnd.id);
      b.insertBefore(idchip, b.children[1]||null);
    }
    if(fnd.waived){badge(b, "waived", "st-note");}
  })(findings[fi]||{});
}
if(findings.length===0){line(flist,"(no findings)");}
armList(flist);
var tlist=document.getElementById("source-targets");
for(n=0;n<nodes.length;n++){
  (function(node){
    addRow(tlist, node.target||"", node.kind||"target", "", "", function(){ showSourceFor(node.target||"", node.kind||""); });
  })(nodes[n]||{});
}
if(nodes.length===0){line(tlist,"(no targets)");}
armList(tlist);
setSR("diff-sr", "Diff: "+String(diff.changeCount||0)+" changes, "+String(sum.match||0)+" match, "+String(sum.divergent||0)+" divergent, "+String(sum.uncertain||0)+" uncertain");
var dt=document.getElementById("diff-tiles");
tile(dt, sum.divergent||0, "Divergent");
tile(dt, sum.onlyInternal||0, "Only internal");
tile(dt, sum.onlyEngine||0, "Only engine");
tile(dt, sum.uncertain||0, "Uncertain");
tile(dt, diff.changeCount||0, "Changes");
var dlist=document.getElementById("diff-list");
var r;
for(r=0;r<rows.length;r++){
  (function(row){
    addRow(dlist, row.path||"", row.kind||"", statusOf(row), "", function(){ showDiff(row); });
  })(rows[r]||{});
}
if(rows.length===0){line(dlist,"(no differential rows)");}
armList(dlist);
setSR("diagnostics-sr", "Diagnostics: "+String(diags.length)+" surfaced");
var ylist=document.getElementById("diagnostics-list");
var d;
for(d=0;d<diags.length;d++){
  (function(ent){
    addRow(ylist, ent.code||"", "diagnostic", "", ent.message||"", function(){ showDiag(ent); });
  })(diags[d]||{});
}
if(diags.length===0){line(ylist,"(none surfaced)");}
armList(ylist);
var tabs=document.querySelectorAll("[role=tab]");
for(var ti=0;ti<tabs.length;ti++){
  tabs[ti].addEventListener("click", function(){
    setView(this.getAttribute("data-view"));
    this.focus();
  });
}
document.addEventListener("keydown", function(e){
  var t=e.target;
  if(!t || !t.getAttribute){return;}
  if(t.getAttribute("role")==="tab"){
    var all=[].slice.call(document.querySelectorAll("[role=tab]"));
    var i=all.indexOf(t);
    if(e.key===K.right){e.preventDefault();focusTab(i+1);}
    else if(e.key===K.left){e.preventDefault();focusTab(i-1);}
    else if(e.key===K.home){e.preventDefault();focusTab(0);}
    else if(e.key===K.end){e.preventDefault();focusTab(all.length-1);}
    else if(isActivate(e)){e.preventDefault();setView(t.getAttribute("data-view"));}
    return;
  }
  if(t.id==="diag-doc" && e.key===K.esc){e.preventDefault();backOut(t);return;}
  if(t.getAttribute("role")==="option"){
    var list=t.parentNode;
    var opts=[].slice.call(list.querySelectorAll("[role=option]"));
    var oi=opts.indexOf(t);
    if(oi<0){return;}
    if(e.key===K.down){e.preventDefault();markOpt(opts,(oi+1)%opts.length);}
    else if(e.key===K.up){e.preventDefault();markOpt(opts,(oi-1+opts.length)%opts.length);}
    else if(e.key===K.home){e.preventDefault();markOpt(opts,0);}
    else if(e.key===K.end){e.preventDefault();markOpt(opts,opts.length-1);}
    else if(isActivate(e)){e.preventDefault();t.click();}
    else if(e.key===K.esc){e.preventDefault();backOut(t);}
  }
});
})();`

var remoteRefPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]+src\s*=`),
	regexp.MustCompile(`(?i)<link[^>]+href\s*=`),
	regexp.MustCompile(`(?i)<img\b[^>]*\bsrc\s*=`),
	regexp.MustCompile(`(?i)<iframe\b`),
	regexp.MustCompile(`(?i)@import\b`),
	regexp.MustCompile(`(?i)url\(\s*['"]?https?:`),
	regexp.MustCompile(`(?i)(src|href)\s*=\s*['"]\s*https?:`),
	regexp.MustCompile(`(?i)(src|href)\s*=\s*['"]\s*//`),
	regexp.MustCompile(`(?i)\bfetch\s*\(`),
	regexp.MustCompile(`(?i)XMLHttpRequest`),
	regexp.MustCompile(`(?i)new\s+WebSocket\s*\(`),
}

// RemoteRefs reports resource-loading patterns that would need a network.
// JSON string contents inside the data island are excluded (inert data).
func RemoteRefs(html []byte) []string {
	island := dataIsland(html)
	shell := html
	if island != nil {
		shell = bytes.Replace(html, island, nil, 1)
	}
	var hits []string
	seen := map[string]struct{}{}
	for _, re := range remoteRefPatterns {
		if loc := re.Find(shell); loc != nil {
			s := string(loc)
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			hits = append(hits, s)
		}
	}
	return hits
}

func dataIsland(html []byte) []byte {
	start := []byte(`id="` + dataID + `">`)
	i := bytes.Index(html, start)
	if i < 0 {
		return nil
	}
	i += len(start)
	end := bytes.Index(html[i:], []byte("</script>"))
	if end < 0 {
		return nil
	}
	return html[i : i+end]
}

// DataIslandJSON returns the JSON text stored in the inert data island.
func DataIslandJSON(html []byte) ([]byte, error) {
	raw := dataIsland(html)
	if raw == nil {
		return nil, fmt.Errorf("report html: missing data island")
	}
	return raw, nil
}
