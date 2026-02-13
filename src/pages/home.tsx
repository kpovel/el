import { Layout } from "./layout.js";

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Oswald:wght@400;500;600;700&family=Barlow+Condensed:wght@400;500;600;700&display=swap');

  :root {
    --bg: #0e0e0e;
    --fg: #e8e8e8;
    --dim: #555;
    --red: #e83030;
    --red-dim: #6b1a1a;
    --green: #28c840;
    --green-dim: #1a4a22;
    --amber: #e8a020;
  }

  body {
    font-family: 'Barlow Condensed', sans-serif;
    background: var(--bg);
    color: var(--fg);
  }

  .font-stencil { font-family: 'Bebas Neue', sans-serif; }
  .font-heading { font-family: 'Oswald', sans-serif; }

  @keyframes wipe-down {
    from { clip-path: inset(0 0 100% 0); }
    to { clip-path: inset(0); }
  }

  @keyframes type-in {
    from { max-width: 0; }
    to { max-width: 100%; }
  }

  @keyframes border-draw {
    0% { clip-path: polygon(0 0, 0 0, 0 0, 0 0); }
    25% { clip-path: polygon(0 0, 100% 0, 100% 0, 0 0); }
    50% { clip-path: polygon(0 0, 100% 0, 100% 100%, 0 100%); }
    100% { clip-path: polygon(0 0, 100% 0, 100% 100%, 0 100%); }
  }

  @keyframes pulse-bar {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 0.6; }
  }

  .wipe-1 { animation: wipe-down 0.5s ease-out 0.05s both; }
  .wipe-2 { animation: wipe-down 0.5s ease-out 0.15s both; }
  .wipe-3 { animation: wipe-down 0.5s ease-out 0.25s both; }
  .wipe-4 { animation: wipe-down 0.5s ease-out 0.35s both; }
  .wipe-5 { animation: wipe-down 0.5s ease-out 0.45s both; }
  .wipe-6 { animation: wipe-down 0.5s ease-out 0.55s both; }

  .cell {
    border: 1px solid #222;
    position: relative;
  }

  .cell-accent {
    border: 1px solid var(--red-dim);
  }

  .cell::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 6px;
    height: 6px;
    border-top: 1px solid #444;
    border-left: 1px solid #444;
    pointer-events: none;
  }

  .tag {
    font-family: 'Bebas Neue', sans-serif;
    font-size: 14px;
    letter-spacing: 0.35em;
    text-transform: uppercase;
    color: var(--dim);
  }

  .divider {
    height: 1px;
    background: linear-gradient(90deg, #333 50%, transparent);
  }

  .htmx-settling {
    opacity: 0.4;
    transition: opacity 0.2s ease;
  }
`;

export function HomePage() {
  const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const fmt = (d: Date) => d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: localTz });
  const now = Date.now();
  const pmLabels = [0, 6, 12, 18].map((h) => fmt(new Date(now - (24 - h) * 60 * 60 * 1000)));

  return (
    <Layout
      title="BLACKOUT — Grid Failure Monitor"
      styles={styles}
      bodyClass="min-h-screen"
    >
      <div className="min-h-screen flex flex-col">
        <header className="px-6 md:px-10 pt-8 pb-6 wipe-1">
          <div className="flex items-start justify-between">
            <div>
              <div className="tag mb-2">GRID FAILURE DETECTION SYSTEM</div>
              <h1 className="font-stencil text-[clamp(3.5rem,12vw,9rem)] leading-[0.9] tracking-wide">
                BLACK
                <span className="text-[var(--red)]">OUT</span>
              </h1>
            </div>
            <div className="text-right mt-2">
              <div className="tag">NODE STATUS</div>
              <div className="font-heading text-sm font-semibold mt-1 flex items-center gap-2 justify-end">
                <span className="w-2 h-2 rounded-full bg-[var(--green)]" style={{ boxShadow: "0 0 6px var(--green)" }} />
                ONLINE
              </div>
              <div className="text-[11px] text-[var(--dim)] mt-0.5">RPI5 • BLE • P:6969</div>
            </div>
          </div>
        </header>

        <div className="flex-1 px-6 md:px-10">
          <div className="divider mb-8" />

          <div className="grid grid-cols-12 gap-4 mb-8 wipe-2">
            <div className="col-span-12 lg:col-span-5">
              <div className="cell cell-accent h-full flex flex-col items-center justify-center text-center p-8">
                <div className="tag mb-3">AC GRID INPUT</div>
                <div
                  hx-get="/api/grid-status"
                  hx-trigger="load, every 15s"
                  hx-swap="innerHTML"
                >
                  <div className="flex items-center justify-center gap-6">
                    <div className="w-4 h-4 rounded-full bg-[var(--dim)]" style={{ flexShrink: 0 }} />
                    <div className="font-stencil text-[120px] leading-none tracking-wider text-[var(--dim)]">
                      — — —
                    </div>
                  </div>
                  <div className="w-full h-px bg-[#333] my-5" />
                  <div className="flex items-center gap-8 text-sm">
                    <div className="text-center">
                      <div className="text-[var(--dim)] text-[11px] tracking-[0.2em]">VOLTAGE</div>
                      <div className="font-stencil text-2xl text-[var(--fg)]">—</div>
                    </div>
                    <div className="text-center">
                      <div className="text-[var(--dim)] text-[11px] tracking-[0.2em]">INPUT</div>
                      <div className="font-stencil text-2xl text-[var(--fg)]">—</div>
                    </div>
                    <div className="text-center">
                      <div className="text-[var(--dim)] text-[11px] tracking-[0.2em]">OUTPUT</div>
                      <div className="font-stencil text-2xl text-[var(--fg)]">—</div>
                    </div>
                    <div className="text-center">
                      <div className="text-[var(--dim)] text-[11px] tracking-[0.2em]">BATTERY</div>
                      <div className="font-stencil text-2xl text-[var(--fg)]">—</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="col-span-12 lg:col-span-7">
              <div
                className="grid grid-cols-2 gap-4 h-full"
                hx-get="/api/stats"
                hx-trigger="load, every 30s"
                hx-swap="innerHTML"
              >
                {[
                  { tag: "INCIDENTS / 24H", val: "—", color: "var(--red)" },
                  { tag: "UPTIME RATIO", val: "—", color: "var(--green)" },
                  { tag: "TOTAL DOWNTIME", val: "—", color: "var(--amber)" },
                  { tag: "PEAK OUTAGE", val: "—", color: "var(--fg)" },
                ].map((s, i) => (
                  <div key={i} className="cell p-5 flex flex-col justify-between">
                    <div className="tag">{s.tag}</div>
                    <div className="font-stencil text-5xl mt-3" style={{ color: s.color }}>
                      {s.val}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="wipe-3 mb-8">
            <div className="cell p-6">
              <div className="flex items-center justify-between mb-5">
                <div className="tag">24-HOUR POWER MAP</div>
                <div className="flex items-center gap-5">
                  <span className="flex items-center gap-2 text-[10px] text-[var(--dim)]">
                    <span className="w-3 h-2" style={{ background: "var(--fg)", opacity: 0.15 }} />
                    NOMINAL
                  </span>
                  <span className="flex items-center gap-2 text-[10px] text-[var(--dim)]">
                    <span className="w-3 h-2" style={{ background: "var(--red)" }} />
                    FAILURE
                  </span>
                </div>
              </div>
              <div
                className="flex gap-[2px] items-end"
                style={{ height: "56px" }}
                hx-get="/api/power-map"
                hx-trigger="load, every 30s"
                hx-swap="innerHTML"
              >
                {Array.from({ length: 96 }).map((_, i) => (
                  <div
                    key={i}
                    className="flex-1 min-w-[5px]"
                    style={{
                      height: "50%",
                      background: "#1a1a1a",
                      opacity: 1,
                    }}
                  />
                ))}
              </div>
              <div className="flex justify-between tag mt-3">
                <span>{pmLabels[0]}</span>
                <span>{pmLabels[1]}</span>
                <span>{pmLabels[2]}</span>
                <span>{pmLabels[3]}</span>
                <span>NOW</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-4 mb-8">
            <div className="col-span-12 lg:col-span-8 wipe-4">
              <div
                className="cell"
                hx-get="/api/incidents"
                hx-trigger="load, every 30s"
                hx-swap="innerHTML"
              >
                <div className="px-5 py-3 border-b border-[#222] flex items-center justify-between">
                  <div className="tag">INCIDENT LOG</div>
                  <div className="tag text-[var(--dim)]">LOADING...</div>
                </div>
              </div>
            </div>

            <div className="col-span-12 lg:col-span-4 wipe-5">
              <div className="cell p-6 h-full flex flex-col justify-between">
                <div>
                  <div className="tag mb-4">SIGNAL CHAIN</div>
                  <div className="space-y-3">
                    {[
                      { label: "EcoFlow R3", proto: "BLE GATT" },
                      { label: "RPi 5", proto: "D-Bus / BlueZ" },
                      { label: "Bun Server", proto: "HTTP :6969" },
                      { label: "Pico 2W", proto: "LED Mirror" },
                    ].map((n, i) => (
                      <div key={i}>
                        <div className="flex items-center gap-3">
                          <span className="font-stencil text-lg text-[var(--dim)] w-5">{i + 1}</span>
                          <span className="font-heading text-sm font-semibold">{n.label}</span>
                        </div>
                        <div className="text-[10px] text-[var(--dim)] ml-8">{n.proto}</div>
                        {i < 3 && (
                          <div className="ml-[9px] mt-1 mb-1 w-px h-3 bg-[#333]" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="mt-6 pt-4 border-t border-[#222]">
                  <div className="flex flex-wrap gap-2">
                    {["ECDH", "AES-128", "MD5", "CRC8", "PROTOBUF"].map((t) => (
                      <span key={t} className="tag px-2 py-1 border border-[#333]">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="wipe-6 mb-4">
            <div className="flex items-center justify-between">
              <div
                className="flex gap-2"
                hx-get="/api/weekly"
                hx-trigger="load, every 60s"
                hx-swap="innerHTML"
              >
                {Array.from({ length: 7 }).map((_, i) => (
                  <div
                    key={i}
                    className="cell w-14 h-14 flex flex-col items-center justify-center"
                  >
                    <div className="font-stencil text-lg text-[var(--dim)]">—</div>
                    <div className="text-[8px] text-[var(--dim)] tracking-widest">---</div>
                  </div>
                ))}
              </div>
              <div className="tag">WEEKLY PATTERN</div>
            </div>
          </div>
        </div>

        <footer className="px-6 md:px-10 py-4 mt-auto">
          <div className="divider mb-4" />
          <div className="tag">
            BLACKOUT MONITOR v1 • ECOFLOW RIVER 3
          </div>
        </footer>
      </div>
    </Layout>
  );
}
