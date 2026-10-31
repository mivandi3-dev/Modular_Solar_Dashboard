// Demo način (Postavke → Isprobaj s primjerom podataka): izmišljena elektrana od 30 kWp s baterijom, uvijek za
// trenutni trenutak – za razgledavanje bez poslužitelja i za pregled aplikacije u trgovini. Podaci nisu stvarni.
"use strict";

window.SolariDemo = (() => {
  const KWP = 30, DAY = 864e5;
  const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const midnight = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const doy = (d) => Math.round((midnight(d) - new Date(d.getFullYear(), 0, 1)) / DAY);
  // ponovljiv "slučajni" broj za dan (oblačnost), 0–1
  const noise = (d) => { const x = Math.sin(d.getFullYear() * 374761 + doy(d) * 668265) * 43758.5453; return x - Math.floor(x); };
  const season = (d) => 0.5 - 0.5 * Math.cos(2 * Math.PI * (doy(d) - 10) / 365);  // 0 zimi, 1 ljeti
  const sunHours = (d) => { const s = season(d); return [7.4 - 2.2 * s, 16.4 + 4.6 * s]; };  // izlazak i zalazak (h)
  const dayKwh = (d) => KWP * (1.0 + 4.0 * season(d)) * (0.45 + 0.55 * noise(d));
  const hhmm = (h) => `${String(Math.floor(h)).padStart(2, "0")}:${String(Math.round((h % 1) * 60) % 60).padStart(2, "0")}`;

  // snaga u satu dana h (kW): sinus između izlaska i zalaska, s malo oblaka
  function powerAt(d, h) {
    const [rise, set] = sunHours(d);
    if (h <= rise || h >= set) return 0;
    const peak = dayKwh(d) / ((set - rise) * 2 / Math.PI);
    const cloud = 0.85 + 0.15 * Math.sin(h * 7.3 + doy(d));
    return Math.max(0, peak * Math.sin(Math.PI * (h - rise) / (set - rise)) * cloud);
  }

  // potrošnja zgrade (kW): stalnih 1,6 kW, više danju
  const loadAt = (h) => 1.6 + (h > 7 && h < 19 ? 1.4 * Math.sin(Math.PI * (h - 7) / 12) : 0);
  // redak dana kao /api/v1/dashboard: [datum, proizvodnja, potrošnja, iz mreže, u mrežu] (kWh); share = dio dana koji je prošao
  function dayRow(d, kwh, share) {
    const load = 55 * share, self = Math.min(kwh * 0.45, load);
    return [iso(d), +kwh.toFixed(2), +load.toFixed(2), +(load - self).toFixed(2), +(kwh - self).toFixed(2)];
  }

  function dashboard(template) {
    const now = new Date(), today = midnight(now), hNow = (now - today) / 36e5;
    const curve = [];
    let todayKwh = 0;
    for (let h = 0; h <= hNow; h += 5 / 60) {
      const kw = powerAt(today, h);
      todayKwh += kw * 5 / 60;
      curve.push([Math.round(today / 1000 + h * 3600), +kw.toFixed(2), +loadAt(h).toFixed(2)]);
    }
    const daily = [];
    for (let i = 59; i >= 1; i--) {
      daily.push(dayRow(new Date(today - i * DAY), dayKwh(new Date(today - i * DAY)), 1));
    }
    daily.push(dayRow(today, todayKwh, hNow / 24));
    const monthly = [];
    let best = { month: "", kwh: 0 }, bestDay = { date: "", kwh: 0 }, total = 0, year = [0, 0];
    for (let m = 23; m >= 0; m--) {
      const first = new Date(today.getFullYear(), today.getMonth() - m, 1);
      let kwh = 0;
      for (let d = new Date(first); d.getMonth() === first.getMonth() && d <= today; d = new Date(d.getTime() + DAY)) {
        const k = d.getTime() === today.getTime() ? todayKwh : dayKwh(d);
        kwh += k;
        if (k > bestDay.kwh) bestDay = { date: iso(d), kwh: k };
        if (first.getFullYear() === today.getFullYear()) year[0] += k;
        else if (first.getFullYear() === today.getFullYear() - 1 && d.getMonth() <= today.getMonth()) year[1] += k;
      }
      monthly.push([iso(first), +kwh.toFixed(2)]);
      if (kwh > best.kwh) best = { month: iso(first), kwh };
      total += kwh;
    }
    const power = curve.length ? curve[curve.length - 1][1] : 0;
    const monthKwh = monthly[monthly.length - 1][1];
    const firstDay = new Date(today.getFullYear() - 2, today.getMonth(), 1);
    const weather = { ...template.weather, is_day: hNow > sunHours(today)[0] && hNow < sunHours(today)[1] ? 1 : 0,
      temperature: +(6 + 18 * season(today)).toFixed(1), radiation_wm2: Math.round(power / KWP * 900),
      // danas i sljedećih 5 dana (kao poslužitelj)
      days: [0, 1, 2, 3, 4, 5].map((i) => { const d = new Date(today.getTime() + i * DAY), [r, s] = sunHours(d);
        return { ...template.weather.days[Math.min(i, template.weather.days.length - 1)], date: iso(d),
          tmax: +(9 + 19 * season(d) + 3 * noise(d)).toFixed(1), tmin: +(2 + 13 * season(d)).toFixed(1),
          radiation_mj: +(dayKwh(d) / KWP / 0.8 * 3.6).toFixed(2), sunshine_h: +(10 * noise(d)).toFixed(1),  // prognoza ≈ proizvodnja
          sunrise: `${iso(d)}T${hhmm(r)}`, sunset: `${iso(d)}T${hhmm(s)}`, code: noise(d) > 0.6 ? 1 : noise(d) > 0.3 ? 3 : 61 }; }),
      hourly: Array.from({ length: 6 * 24 }, (_, i) => { const d = new Date(today.getTime() + Math.floor(i / 24) * DAY), h = i % 24;
        return [`${iso(d)}T${String(h).padStart(2, "0")}:00`, Math.round(powerAt(d, h) / KWP * 1000)]; }) };
    const soc = Math.round(35 + 50 * Math.min(1, todayKwh / (dayKwh(today) || 1)));
    return {
      ...template, today: iso(today), now: Math.round(now / 1000), curve, daily, monthly, weather,
      year: [+year[0].toFixed(1), +year[1].toFixed(1)],
      records: { best_day: [bestDay.date, +bestDay.kwh.toFixed(2)], best_month: [best.month, +best.kwh.toFixed(2)],
        first_day: iso(firstDay), peak_power: [Math.round(today / 1000 + 12.5 * 3600), +(KWP * 0.82).toFixed(1)], producing_days: 730 },
      savings: { ...template.savings, first_day: iso(firstDay), today: +(todayKwh * 0.15).toFixed(2), month: +(monthKwh * 0.15).toFixed(2),
        year: +(year[0] * 0.15).toFixed(2), total: +(total * 0.15 + 3200).toFixed(2) },
      realtime: { ...template.realtime, power_kw: power, running: power > 0, stale: false, day_kwh: +todayKwh.toFixed(2),
        month_kwh: monthKwh, total_kwh: +(total + 21500).toFixed(1), updated_at: Math.round(now / 1000), availability: 100,
        load_kw: +loadAt(hNow).toFixed(2),
        extra: { battery_soc: soc, battery_kw: power > 3 ? 1.4 : -0.6, battery_dir: true, inverter_temp: +(24 + power * 1.1).toFixed(1),
          grid_v: 230.6, grid_hz: 50.01 } },
      settings: { ...template.settings, plant_name: "Demo", location: "Zagreb, Hrvatska", peak_power_kwp: KWP, speedo_max_kw: KWP,
        commissioned: `${String(firstDay.getMonth() + 1).padStart(2, "0")}.${firstDay.getFullYear()}.` },
      capabilities: ["battery", "temperature", "grid"], demo: true,
    };
  }

  // Mjesečni izvještaj za demo (isti oblik kao /api/v1/report)
  function report(template, y, m) {
    const first = new Date(y, m - 1, 1), today = midnight(new Date());
    const days = [];
    for (let d = new Date(first); d.getMonth() === first.getMonth() && d < today; d = new Date(d.getTime() + DAY)) {
      const kwh = +dayKwh(d).toFixed(2);
      days.push({ date: iso(d), kwh, load: null, import: null, export: null, self: kwh, savings: +(kwh * 0.15).toFixed(3) });
    }
    const kwh = days.reduce((s, d) => s + d.kwh, 0), best = days.reduce((b, d) => (d.kwh > (b ? b.kwh : -1) ? d : b), null);
    return { ...template, year: y, month: m, plant: "Demo", days, complete: true,
      until: days.length ? days[days.length - 1].date : iso(first), generated: new Date().toISOString().slice(0, 16),
      best_day: best ? { date: best.date, kwh: best.kwh } : null,
      totals: { ...template.totals, kwh: +kwh.toFixed(2), self: +kwh.toFixed(2), savings: +(kwh * 0.15).toFixed(2), co2_kg: +(kwh * 0.4).toFixed(1) } };
  }

  return { dashboard, report };
})();
