(function(){
  "use strict";
  var R = window.R, base = R.base, $ = function(id){ return document.getElementById(id); };
  var loc = R.lang === "ru" ? "ru-RU" : "en-US", data = null;
  var order = ["USD","EUR","GBP","CNY","JPY","CHF","TRY","KZT","BYN","PLN","AED","RUB"];
  function fmt(v){ var d = v >= 10 ? 2 : v >= 1 ? 3 : 4; return v.toLocaleString(loc, {minimumFractionDigits: d, maximumFractionDigits: d}); }
  function rate(usd, c){ return usd[base] / usd[c]; }       // сколько BASE за 1 c
  function spark(pts, cls){
    if (pts.length < 2) return "";
    var min = Math.min.apply(null, pts), max = Math.max.apply(null, pts), span = (max - min) || 1, w = 130, h = 30, p = [];
    for (var i = 0; i < pts.length; i++) p.push((i ? "L" : "M") + (i * w / (pts.length - 1)).toFixed(1) + " " + (h - 3 - (pts[i] - min) / span * (h - 6)).toFixed(1));
    return '<svg class="spark ' + cls + '" viewBox="0 0 130 30" aria-hidden="true"><path d="' + p.join("") + '"/></svg>';
  }
  function render(){
    var usd = data.usd, days = Object.keys(data.hist || {}).sort().slice(-30), rows = [], sel = $("from");
    order.forEach(function(c){
      if (c === base || !usd[c]) return;
      var now = rate(usd, c), pts = [], prev = null;
      days.forEach(function(d){ var h = data.hist[d]; if (h[c] && h[base]) pts.push(h[base] / h[c]); });
      var today = new Date().toISOString().slice(0, 10);
      for (var i = days.length - 1; i >= 0; i--){ var h = data.hist[days[i]]; if (days[i] < today && h[c] && h[base]){ prev = h[base] / h[c]; break; } }
      var ch = prev ? (now / prev - 1) * 100 : null, cls = ch === null || Math.abs(ch) < 0.005 ? "flat" : ch > 0 ? "up" : "down";
      var chs = ch === null ? "—" : (ch > 0 ? "+" : ch < 0 ? "−" : "") + Math.abs(ch).toFixed(2).replace(".", R.lang === "ru" ? "," : ".") + "%";
      var per = (c === "JPY" || c === "KZT") ? 100 : 1;
      rows.push('<tr><td><span class="code">' + c + '</span> <span class="name">' + (R.names[c] || "") + (per > 1 ? " (" + R.per + " " + per + ")" : "") + '</span></td>' +
        '<td class="n val">' + fmt(now * per) + '</td><td class="n ' + cls + '">' + chs + '</td><td class="t">' + spark(pts.map(function(x){ return x * per; }), cls) + '</td></tr>');
      if (!sel.dataset.done) sel.insertAdjacentHTML("beforeend", '<option value="' + c + '">' + c + " · " + (R.names[c] || c) + "</option>");
    });
    sel.dataset.done = 1;
    $("rows").innerHTML = rows.join("");
    var u = new Date(data.updated);
    $("upd").textContent = R.upd + ": " + u.toLocaleString(loc, {day: "numeric", month: "long", hour: "2-digit", minute: "2-digit"});
    conv();
  }
  function conv(){
    if (!data) return;
    var a = parseFloat(($("amt").value || "").replace(/\s/g, "").replace(",", ".")), c = $("from").value;
    $("res").textContent = isFinite(a) && c ? "= " + (a * rate(data.usd, c)).toLocaleString(loc, {maximumFractionDigits: 2}) + " " + base : "—";
  }
  $("amt").addEventListener("input", conv); $("from").addEventListener("change", conv);
  fetch("/data/rates.json", {cache: "no-cache"}).then(function(r){ if (!r.ok) throw 0; return r.json(); })
    .then(function(j){ if (!j.usd || !j.usd[base]) throw 0; data = j; render(); }).catch(function(){});
})();
