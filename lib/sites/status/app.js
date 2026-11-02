(function(){
  "use strict";
  var T = window.T, $ = function(id){ return document.getElementById(id); };
  function dur(s){
    var d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
    return d ? d + " " + T.d + " " + h + " " + T.h : h ? h + " " + T.h + " " + m + " " + T.m : m + " " + T.m;
  }
  function when(iso){
    try { return new Date(iso).toLocaleString(T.lang === "ru" ? "ru-RU" : "en-GB", {day:"numeric", month:"short", hour:"2-digit", minute:"2-digit"}); }
    catch(e){ return iso; }
  }
  function meter(id, pct){ var el = $(id); el.style.width = pct + "%"; if (pct >= 85) el.className = "hi"; }
  function nodata(){ $("state").setAttribute("data-s", "none"); $("state-text").textContent = T.nodata; bars([]); }
  function bars(days){
    var box = $("bars"), html = [], sum = 0, n = 0, map = {}, i, d, k, p, c, t;
    for (i = 0; i < days.length; i++) map[days[i].d] = days[i].p;
    var now = new Date();
    for (i = 89; i >= 0; i--){
      d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
      k = d.toISOString().slice(0, 10); p = map[k];
      if (p === undefined){ c = ""; t = k + ": " + T.nohist; }
      else { sum += p; n++; c = p >= 99 ? "ok" : p >= 90 ? "warn" : "bad"; t = k + ": " + p.toFixed(2) + "%"; }
      html.push('<i class="' + c + '" title="' + t + '"></i>');
    }
    box.innerHTML = html.join("");
    $("avg").textContent = n ? (sum / n).toFixed(2) + "% " + T.avg : "";
  }
  fetch("/data/status.json", {cache: "no-store"}).then(function(r){ if (!r.ok) throw 0; return r.json(); }).then(function(s){
    var age = (Date.now() - Date.parse(s.updated)) / 1000;
    var warn = age > 600 || s.load[0] > s.cpus * 2 || s.mem_pct > 95 || s.disk_pct > 95;
    $("state").setAttribute("data-s", warn ? "warn" : "ok");
    $("state-text").textContent = warn ? T.warn : T.ok;
    $("updated").textContent = T.upd + " " + when(s.updated);
    $("m-up").textContent = dur(s.uptime_s);
    $("m-load").textContent = s.load[0].toFixed(2);
    $("m-cpu").textContent = s.load.map(function(x){ return x.toFixed(2); }).join(" · ") + " · " + s.cpus + " " + T.cores;
    $("m-mem").textContent = Math.round(s.mem_pct) + "%"; meter("b-mem", s.mem_pct);
    $("m-disk").textContent = Math.round(s.disk_pct) + "%"; meter("b-disk", s.disk_pct);
    bars(s.days || []);
  }).catch(nodata);
})();
