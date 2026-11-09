$script:SLHtmlTemplate = @'
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1c2330; --muted:#5d6878; --line:#e2e6ec; --accent:#1f5fbf; --accent-soft:#e8f0fc;
  --hi:#b42318; --hi-bg:#fde8e7; --mid:#a35a00; --mid-bg:#fff1dc; --info:#36597d; --info-bg:#e8eef5;
  --l5:#b42318; --l4:#c2570c; --l3:#a16207; --l2:#1d7a46; --l1:#5d6878; --l0:#8a94a3;
  --mono: ui-monospace, "Cascadia Mono", Consolas, monospace;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#11151c; --panel:#181d26; --ink:#e6e9ef; --muted:#9aa4b2; --line:#2a3240; --accent:#6ea0ff; --accent-soft:#1d2a40;
  --hi:#ff8a80; --hi-bg:#3a1d1d; --mid:#ffb35c; --mid-bg:#3a2a14; --info:#9cc0e8; --info-bg:#1c2a3a;
  --l5:#ff8a80; --l4:#ffa366; --l3:#e6c35c; --l2:#6fd39b; --l1:#9aa4b2; --l0:#6b7584; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
header{padding:20px 24px 12px;border-bottom:1px solid var(--line);background:var(--panel)}
h1{margin:0 0 4px;font-size:20px;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
nav{display:flex;gap:2px;flex-wrap:wrap;padding:0 16px;background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
nav button{border:0;background:none;color:var(--muted);padding:10px 12px;font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button:hover{color:var(--ink)}
nav button.on{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
nav .n{display:inline-block;margin-left:6px;font-size:11px;background:var(--accent-soft);color:var(--accent);border-radius:9px;padding:0 6px}
main{padding:16px 24px 40px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .v{font-size:22px;font-weight:650}
.card .k{color:var(--muted);font-size:12px}
.card.hi .v{color:var(--hi)} .card.mid .v{color:var(--mid)}
h2{font-size:15px;margin:22px 0 8px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-size:13px}
.meta dt{color:var(--muted)} .meta dd{margin:0;word-break:break-word}
.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 10px}
.bar input[type=search]{flex:1 1 260px;max-width:420px;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);font:inherit}
.bar .cnt{color:var(--muted);font-size:12px}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:6px;padding:6px 10px;font:inherit;font-size:13px;cursor:pointer}
.btn:hover{border-color:var(--accent);color:var(--accent)}
details.cols{position:relative}
details.cols summary{list-style:none}
details.cols .pop{position:absolute;z-index:10;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;max-height:360px;overflow:auto;min-width:220px;box-shadow:0 6px 24px rgba(0,0,0,.12)}
details.cols label{display:block;font-size:13px;white-space:nowrap}
.wrap{overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;max-height:calc(100vh - 200px)}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{position:sticky;top:0;background:var(--panel);z-index:2;white-space:nowrap;cursor:pointer;user-select:none;font-weight:600}
thead tr.f th{top:29px;cursor:default;padding:3px 4px}
thead tr.f input{width:100%;min-width:60px;padding:3px 5px;border:1px solid var(--line);border-radius:4px;background:var(--bg);color:var(--ink);font:inherit;font-size:12px}
th .s{color:var(--accent);font-size:10px;margin-left:3px}
tbody tr:hover td{background:var(--accent-soft)}
td.wide{min-width:240px}
td.path{font-family:var(--mono);font-size:12px;word-break:break-all;min-width:220px}
.lv{display:inline-block;padding:0 6px;border-radius:4px;font-weight:600;font-size:12px;white-space:nowrap}
.lv5{color:var(--l5)} .lv4{color:var(--l4)} .lv3{color:var(--l3)} .lv2{color:var(--l2)} .lv1{color:var(--l1)} .lv0{color:var(--l0)}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11.5px;font-weight:600}
.sev.Hoch{background:var(--hi-bg);color:var(--hi)} .sev.Mittel{background:var(--mid-bg);color:var(--mid)} .sev.Info{background:var(--info-bg);color:var(--info)}
.no{color:var(--muted)}
.more{margin:10px 0}
.note{color:var(--muted);font-size:12px;margin:6px 0}
@media (max-width:640px){ header,main{padding-left:16px;padding-right:16px} }
@media print{ nav,.bar{display:none} .wrap{max-height:none;overflow:visible} }
</style>
</head>
<body>
<header><h1 id="t"></h1><div class="sub" id="sub"></div></header>
<nav id="nav"></nav>
<main id="main"></main>
<script type="application/json" id="sl-data">__DATA__</script>
<script>
(function(){
var D = JSON.parse(document.getElementById('sl-data').textContent);
var LV = {'Vollzugriff':5,'Ändern':4,'Lesen+Schreiben':3,'Lesen':2,'Speziell':1,'Kein':0};
var LABELS = {Path:'Pfad',DfsPath:'DFS-Pfad',ShareUnc:'Freigabe',Principal:'Konto',DisplayName:'Anzeigename',ObjectClass:'Typ',
  Enabled:'Aktiv',EffectiveLevel:'Effektiv',NtfsLevel:'NTFS',ShareLevel:'Freigabe-Recht',HasDeny:'Verweigern',ViaNtfs:'Über (NTFS)',
  ViaShare:'Über (Freigabe)',PrincipalSid:'SID',Identity:'Konto',IdentitySid:'SID',IdentityClass:'Typ',Category:'Kategorie',
  AccessType:'Art',Level:'Stufe',Rights:'Rechte (roh)',Inherited:'Geerbt',AppliesTo:'Gilt für',AppliesToThisFolder:'Gilt für Ordner',
  InheritanceFlags:'Vererbung',PropagationFlags:'Weitergabe',Depth:'Tiefe',Owner:'Besitzer',OwnerSid:'Besitzer-SID',
  InheritanceProtected:'Vererbung aus',ExplicitAceCount:'Explizit',AceCount:'ACEs',IsBoundary:'Grenzordner',ScanRoot:'Scan-Wurzel',
  Severity:'Stufe',Object:'Objekt',Detail:'Detail',ComputerName:'Server',ShareName:'Name',LocalPath:'Lokaler Pfad',Description:'Beschreibung',
  Special:'Admin',ScopeName:'Scope',AccessBasedEnumeration:'ABE',EncryptData:'Verschl.',ContinuouslyAvailable:'CA',CachingMode:'Offline-Cache',
  CurrentUsers:'Sitzungen',FullAccess:'Vollzugriff',ChangeAccess:'Ändern',ReadAccess:'Lesen',DenyAccess:'Verweigert',Source:'Quelle',
  AccessRight:'Recht',Kind:'Art',Namespace:'Namespace',NamespaceType:'Typ',FolderState:'Ordnerstatus',TargetPath:'Ziel',
  TargetServer:'Zielserver',TargetShare:'Zielfreigabe',TargetSubPath:'Unterpfad',TargetState:'Zielstatus',
  ReferralPriorityClass:'Priorität',ReferralPriorityRank:'Rang',Member:'Mitglied',Via:'Über',MemberSid:'SID',Stage:'Schritt',
  Target:'Ziel',Message:'Meldung',Readable:'Lesbar',Writeable:'Schreibbar',WriteTestRequested:'Schreibtest',ResponseMilliseconds:'ms',
  Error:'Fehler',User:'Benutzer',GroupName:'Gruppe',FolderName:'Ordner',ContentPath:'Inhaltspfad',PrimaryMember:'Primär',ReadOnly:'Schreibgeschützt',
  StagingQuotaMB:'Staging MB',GroupState:'Gruppenstatus'};
var HIDE = {Matrix:['PrincipalSid','ShareUnc'],Aces:['IdentitySid','InheritanceFlags','PropagationFlags','AppliesToThisFolder','ShareUnc'],
  Folders:['OwnerSid','ScanRoot','ShareUnc'],Members:['PrincipalSid','MemberSid'],ShareAccess:['IdentitySid'],Dfs:['TargetServer','TargetShare','TargetSubPath']};
var WIDE = {AppliesTo:1,ViaNtfs:1,ViaShare:1,Detail:1,Via:1,Message:1,FullAccess:1,ChangeAccess:1,ReadAccess:1};
var PATHCOLS = {Path:1,DfsPath:1,ShareUnc:1,TargetPath:1,LocalPath:1,Target:1,ScanRoot:1,ContentPath:1,Object:1};

function el(tag, attrs, html){ var e=document.createElement(tag); if(attrs) for(var k in attrs) e.setAttribute(k, attrs[k]); if(html!=null) e.innerHTML=html; return e; }
function esc(v){ return String(v).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
function show(v){ if(v===null||v===undefined||v==='') return ''; if(v===true) return 'Ja'; if(v===false) return 'Nein'; return String(v); }
function cell(col, v){
  var s = show(v);
  if(s==='') return '<span class="no">–</span>';
  if(LV.hasOwnProperty(s) && /Level$|^Level$/.test(col)) return '<span class="lv lv'+LV[s]+'">'+esc(s)+'</span>';
  if(col==='AccessType'){ return s==='Deny' ? '<span class="lv lv5">Verweigern</span>' : 'Erlauben'; }
  if(col==='Severity') return '<span class="sev '+esc(s)+'">'+esc(s)+'</span>';
  return esc(s);
}

document.getElementById('t').textContent = D.title;
document.title = D.title;
var m = D.meta || {};
document.getElementById('sub').textContent = 'Erstellt ' + (m.GeneratedAt||'') + ' von ' + (m.GeneratedBy||'') + ' auf ' + (m.RunOn||'') + ' · ShareLens ' + (m.Version||'');

var tables = {}; D.tables.forEach(function(t){ tables[t.key]=t; });
var nav = document.getElementById('nav'), main = document.getElementById('main');
var views = [{key:'_overview', title:'Übersicht'}].concat(D.tables.filter(function(t){ return t.total>0; }));
var state = {};

views.forEach(function(v){
  var b = el('button', {'data-k':v.key}, esc(v.title) + (v.total!=null ? '<span class="n">'+v.total+'</span>' : ''));
  b.onclick = function(){ open(v.key); };
  nav.appendChild(b);
});

function open(key){
  [].forEach.call(nav.children, function(b){ b.classList.toggle('on', b.getAttribute('data-k')===key); });
  main.innerHTML = '';
  try { history.replaceState(null,'','#'+key); } catch(e){}
  if(key==='_overview') overview(); else table(tables[key]);
}

function count(key, fn){ var t=tables[key]; if(!t) return 0; return fn ? t.rows.filter(fn).length : t.total; }

function overview(){
  var f = tables.Findings ? tables.Findings.rows : [];
  var cards = [
    ['Freigaben', count('Shares')], ['DFS-Ziele', count('Dfs', function(r){return r.Kind==='FolderTarget';})],
    ['Ordner gelesen', count('Folders')], ['Grenzordner', count('Folders', function(r){return r.IsBoundary===true;})],
    ['Zugriffszeilen', count('Matrix')], ['Befunde Hoch', f.filter(function(r){return r.Severity==='Hoch';}).length, 'hi'],
    ['Befunde Mittel', f.filter(function(r){return r.Severity==='Mittel';}).length, 'mid'], ['Fehler', count('Errors')]
  ];
  var c = el('div',{'class':'cards'});
  cards.forEach(function(x){ c.appendChild(el('div',{'class':'card '+(x[2]||'')},'<div class="v">'+x[1]+'</div><div class="k">'+esc(x[0])+'</div>')); });
  main.appendChild(c);
  var dl = el('dl',{'class':'meta'});
  var ML = {Servers:'Server',Namespaces:'DFS-Namespaces',Depth:'Scan-Tiefe',GroupExpansion:'Gruppenauflösung',ScanRoots:'Scan-Wurzeln',DurationSec:'Dauer (s)',GeneratedBy:'Erstellt von',RunOn:'Ausgeführt auf'};
  Object.keys(ML).forEach(function(k){ dl.appendChild(el('dt',null,esc(ML[k]))); dl.appendChild(el('dd',null,esc(show(m[k]))||'–')); });
  main.appendChild(el('h2',null,'Rahmendaten'));
  main.appendChild(dl);
  if(tables.Findings && tables.Findings.total){ main.appendChild(el('h2',null,'Befunde')); table(tables.Findings, true); }
  main.appendChild(el('p',{'class':'note'},'Effektiv = Schnittmenge aus Freigabe- und NTFS-Recht am jeweiligen Ordner. Gruppen sind bis auf Benutzer aufgelöst; Jeder/Authentifizierte Benutzer/Domänen-Benutzer gelten für alle Konten.'));
}

function table(t, embedded){
  var st = state[t.key] || (state[t.key] = {q:'', f:{}, sort:null, dir:1, limit:500, hidden:null});
  var cols = []; var seen = {};
  t.rows.forEach(function(r){ for(var k in r) if(!seen[k]){ seen[k]=1; cols.push(k); } });
  if(st.hidden===null){ st.hidden = {}; (HIDE[t.key]||[]).forEach(function(c){ st.hidden[c]=1; }); }

  var box = el('div');
  var bar = el('div',{'class':'bar'});
  var q = el('input',{type:'search',placeholder:'Suchen in allen Spalten …'}); q.value = st.q;
  var cnt = el('span',{'class':'cnt'});
  var csv = el('button',{'class':'btn'},'CSV (gefiltert)');
  var cd = el('details',{'class':'cols'}); cd.appendChild(el('summary',{'class':'btn'},'Spalten'));
  var pop = el('div',{'class':'pop'});
  cols.forEach(function(c){
    var l = el('label'); var cb = el('input',{type:'checkbox'}); cb.checked = !st.hidden[c];
    cb.onchange = function(){ if(cb.checked) delete st.hidden[c]; else st.hidden[c]=1; render(); };
    l.appendChild(cb); l.appendChild(document.createTextNode(' '+(LABELS[c]||c))); pop.appendChild(l);
  });
  cd.appendChild(pop);
  bar.appendChild(q); bar.appendChild(cd); bar.appendChild(csv); bar.appendChild(cnt);
  if(!embedded) box.appendChild(bar);
  if(t.total > t.rows.length) box.appendChild(el('p',{'class':'note'},'Im HTML sind die ersten '+t.rows.length+' von '+t.total+' Zeilen enthalten – vollständig in CSV/XLSX.'));
  var wrap = el('div',{'class':'wrap'}); box.appendChild(wrap);
  var more = el('div',{'class':'more'}); box.appendChild(more);
  main.appendChild(box);

  var timer;
  q.oninput = function(){ clearTimeout(timer); timer=setTimeout(function(){ st.q=q.value; st.limit=500; render(); },150); };

  function filtered(){
    var needle = st.q.toLowerCase();
    var fk = Object.keys(st.f).filter(function(k){ return st.f[k]; });
    var rows = t.rows.filter(function(r){
      if(needle){ var hit=false; for(var k in r){ if(show(r[k]).toLowerCase().indexOf(needle)>=0){ hit=true; break; } } if(!hit) return false; }
      for(var i=0;i<fk.length;i++){ var term=st.f[fk[i]].toLowerCase(); var val=show(r[fk[i]]).toLowerCase();
        if(term.charAt(0)==='='){ if(val!==term.slice(1)) return false; }
        else if(term.charAt(0)==='!'){ if(val.indexOf(term.slice(1))>=0) return false; }
        else if(val.indexOf(term)<0) return false; }
      return true;
    });
    if(st.sort){
      var c=st.sort, d=st.dir;
      rows = rows.slice().sort(function(a,b){
        var x=a[c], y=b[c];
        if(LV.hasOwnProperty(x) && LV.hasOwnProperty(y)){ x=LV[x]; y=LV[y]; }
        if(typeof x==='number' && typeof y==='number') return (x-y)*d;
        return show(x).localeCompare(show(y),'de',{numeric:true})*d;
      });
    }
    return rows;
  }

  function render(){
    var vis = cols.filter(function(c){ return !st.hidden[c]; });
    var rows = filtered();
    cnt.textContent = rows.length + ' von ' + t.total + ' Zeilen';
    var h = '<table><thead><tr>';
    vis.forEach(function(c){ h += '<th data-c="'+esc(c)+'">'+esc(LABELS[c]||c)+(st.sort===c?'<span class="s">'+(st.dir>0?'▲':'▼')+'</span>':'')+'</th>'; });
    h += '</tr>';
    if(!embedded){ h += '<tr class="f">'; vis.forEach(function(c){ h += '<th><input data-f="'+esc(c)+'" value="'+esc(st.f[c]||'')+'" placeholder="Filter"></th>'; }); h += '</tr>'; }
    h += '</thead><tbody>';
    var n = Math.min(rows.length, st.limit);
    for(var i=0;i<n;i++){ var r=rows[i]; h+='<tr>'; vis.forEach(function(c){ h+='<td'+(PATHCOLS[c]?' class="path"':(WIDE[c]?' class="wide"':''))+'>'+cell(c,r[c])+'</td>'; }); h+='</tr>'; }
    h += '</tbody></table>';
    wrap.innerHTML = h;
    [].forEach.call(wrap.querySelectorAll('thead tr:first-child th'), function(th){
      th.onclick = function(){ var c=th.getAttribute('data-c'); if(st.sort===c) st.dir=-st.dir; else { st.sort=c; st.dir=1; } render(); };
    });
    [].forEach.call(wrap.querySelectorAll('input[data-f]'), function(inp){
      var tm; inp.oninput = function(){ clearTimeout(tm); tm=setTimeout(function(){ st.f[inp.getAttribute('data-f')]=inp.value; st.limit=500; var pos=inp.selectionStart; var name=inp.getAttribute('data-f'); render(); var again=wrap.querySelector('input[data-f="'+name+'"]'); if(again){ again.focus(); try{again.setSelectionRange(pos,pos);}catch(e){} } },250); };
    });
    more.innerHTML = '';
    if(rows.length > n){ var b=el('button',{'class':'btn'},'Weitere '+Math.min(1000, rows.length-n)+' anzeigen'); b.onclick=function(){ st.limit+=1000; render(); }; more.appendChild(b); }
    csv.onclick = function(){
      var lines = [vis.map(function(c){ return '"'+(LABELS[c]||c).replace(/"/g,'""')+'"'; }).join(';')];
      rows.forEach(function(r){ lines.push(vis.map(function(c){ return '"'+show(r[c]).replace(/"/g,'""')+'"'; }).join(';')); });
      var blob = new Blob(['﻿'+lines.join('\r\n')], {type:'text/csv;charset=utf-8'});
      var a = el('a',{href:URL.createObjectURL(blob), download:'ShareLens_'+t.key+'.csv'}); document.body.appendChild(a); a.click(); a.remove();
    };
  }
  render();
}

var start = (location.hash||'').slice(1);
open(tables[start] ? start : '_overview');
})();
</script>
</body>
</html>
'@
