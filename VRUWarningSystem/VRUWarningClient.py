# VRU warning system

import json
import time
import argparse
import os
from datetime import datetime
from zoneinfo import ZoneInfo

# Library imports
from flask import Flask, render_template_string
from flask_socketio import SocketIO
import paho.mqtt.client as mqtt

# Command line arguments to configure MQTT connection
parser = argparse.ArgumentParser(description="On-vehicle VRU Presence system - MQTT client")
parser.add_argument("--mqtt-broker", required=True, help="MQTT broker hostname/IP")
parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT broker port")
parser.add_argument("--mqtt-topic", required=True, help="MQTT topic to subscribe")
parser.add_argument("--mqtt-username", required=True, help="MQTT username")
parser.add_argument("--mqtt-password", required=True, help="MQTT password")
parser.add_argument("--web-host", default="0.0.0.0", help="Web server host")
parser.add_argument("--web-port", type=int, default=5000, help="Web server port")

args = parser.parse_args()

USER_TZ = ZoneInfo("Europe/Rome")

# Socket.io configuration with Flask
app = Flask(__name__)
app.config["SECRET_KEY"] = "vru-secret"
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=True,
    engineio_logger=True
)

last_payload = None

# Theshold logic for displaying the warnings
def determine_vru_level(diff: int):
    if diff < 10:
        return "low", "green"
    elif diff < 20:
        return "medium", "yellow"
    else:
        return "high", "red"

# Paho MQTT Client callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
      print("[MQTT] Connected!")
      client.subscribe(args.mqtt_topic)
      print(f"[MQTT] Subscribed to topic: {args.mqtt_topic}")
    else:
      print(f"[MQTT] Error: cannot connect to broker. Error code: {rc}")
      os._exit(1)

# Called every time a JSON message (over MQTT) is received from the Raspberry Pi
def on_message(client, userdata, msg):
    print("[MQTT] Message received!")
    print(f"[MQTT] Data received: {msg.payload.decode()}")

    try:
        data = json.loads(msg.payload.decode())
    except Exception as e:
        print("[MQTT] [ERROR] Invalid JSON format:", e)
        return

    people = int(data.get("people_count", 0))
    global_MACs = int(data.get("global_MACs", 0))

    # We suppose that VRUs are carrying normal smartphone, who should typically use randomized MACs
    # Therefore we estimate the count by subtracting the global MACs from the overall people count
    VRU_count=people-global_MACs

    # Get the current "VRU presence level" based on "VRU_count"
    level, color = determine_vru_level(VRU_count)

    # Take the masurement timestamp and convert it to a human-redable format using the USER_TZ timezone
    now_ts = int(data.get("timestamp", time.time()))
    now_dt = datetime.fromtimestamp(now_ts, tz=USER_TZ)
    string_ts = now_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

    # Debug print: show the information that has been parsed
    print(
        f"[MQTT] [DEBUG] "
        f"Current_time={string_ts}, total_count={people}, global_MACs={global_MACs}, "
        f"VRU_count={VRU_count}, VRU_presence_level={level}"
    )

    # Prepare the data to be sent to the web-based HMI
    payload = {
        "device_id": data.get("device_id"),
        "people_count": people,
        "global_MACs": global_MACs,
        "VRU_count": VRU_count,
        "VRU_presence_level": level,
        "VRU_presence_level_color": color,
        "string_ts": string_ts,
        "interval_seconds": data.get("interval_seconds"),
    }

    print("[HMI] Sending update to web clients via SocketIO")
    global last_payload
    last_payload = payload
    # Send data to HMI via socket.io
    socketio.emit("update", payload)


# MQTT client creation
mqtt_client = mqtt.Client()
mqtt_client.username_pw_set(args.mqtt_username, args.mqtt_password)
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

# Function to start the MQTT reception/network loop thread
def start_mqtt():
    mqtt_client.connect(args.mqtt_broker, args.mqtt_port, 60)
    mqtt_client.loop_start()

# Web-based HMI code -> embedded in the Python code for conveniency
HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>VRU Warning HMI</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>

  <!-- CSS style -->
  <style>
    :root{
      --bg0:#070A12;
      --bg1:#0B1220;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.08);
      --border: rgba(255,255,255,0.12);
      --text:#E5E7EB;
      --muted: rgba(229,231,235,0.68);

      --g:#22c55e;
      --y:#f59e0b;
      --r:#ef4444;

      --glow: 0 0 0 rgba(0,0,0,0);
    }

    *{ box-sizing: border-box; }
    body{
      margin:0;
      color:var(--text);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(1100px 650px at 18% 18%, rgba(255,255,255,0.08), transparent 55%),
        radial-gradient(900px 550px at 80% 45%, rgba(255,255,255,0.06), transparent 55%),
        linear-gradient(160deg, var(--bg0), var(--bg1));
      min-height: 100vh;
      overflow-x: hidden;
    }

    .wrap{
      max-width: 1020px;
      margin: 0 auto;
      padding: 18px 16px 30px;
    }

    .topbar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 12px;
      margin-bottom: 14px;
    }

    .title{
      font-weight: 900;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      font-size: 14px;
      color: rgba(229,231,235,0.92);
    }

    .pill{
      display:flex;
      align-items:center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel);
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }

    .dot{
      width: 9px; height: 9px;
      border-radius: 999px;
      background: rgba(148,163,184,0.9);
      box-shadow: 0 0 0 4px rgba(148,163,184,0.18);
    }

    .main{
      display:grid;
      grid-template-columns: 1.25fr 0.75fr;
      gap: 14px;
    }

    @media (max-width: 860px){
      .main{ grid-template-columns: 1fr; }
    }

    .panel{
      border-radius: 18px;
      border: 1px solid var(--border);
      background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.05));
      box-shadow: 0 24px 65px rgba(0,0,0,0.40);
      overflow:hidden;
      position: relative;
    }

    .statusBanner{
      padding: 18px;
      border-bottom: 1px solid rgba(255,255,255,0.10);
      position: relative;
    }

    .statusRow{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 12px;
      flex-wrap: wrap;
    }

    .statusLeft{
      display:flex;
      align-items:center;
      gap: 14px;
      min-width: 0;
    }

    .levelChip{
      display:flex;
      align-items:center;
      justify-content:center;
      width: 56px;
      height: 56px;
      border-radius: 16px;
      font-weight: 1000;
      font-size: 24px;
      color: rgba(0,0,0,0.86);
      box-shadow: var(--glow);
      flex: 0 0 auto;
      transform: translateZ(0);
      animation: none;
    }

    /* Not used now. Can be used to enable a soft pulse animation for the warning signs. */
    @keyframes pulseSoft{
      0%, 100% { filter: brightness(1); transform: translateZ(0) scale(1); }
      50% { filter: brightness(1.06); transform: translateZ(0) scale(1.02); }
    }

    .labelSmall{
      color: var(--muted);
      font-weight: 800;
      font-size: 12px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .levelText{
      font-size: 34px;
      font-weight: 1000;
      line-height: 1;
      letter-spacing: 1px;
      text-transform: uppercase;
    }

    .countBox{
      text-align: right;
      min-width: 160px;
    }

    .count{
      font-size: 54px;
      font-weight: 1000;
      line-height: 0.95;
    }

    .countSub{
      margin-top: 8px;
      color: var(--muted);
      font-weight: 900;
      font-size: 12px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
    }

    .metaGrid{
      display:grid;
      grid-template-columns: 2.2fr 0.8fr 1.2fr;
      gap: 10px;
      padding: 14px 18px 18px;
    }

    @media (max-width: 860px){
      .metaGrid{ grid-template-columns: 1fr; }
    }

    .card{
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(0,0,0,0.14);
      padding: 12px 14px;
    }

    .k{
      color: var(--muted);
      font-weight: 900;
      font-size: 12px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      margin-bottom: 6px;
    }

    .v{
      font-weight: 900;
      font-size: 15px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Right-side visual panel */
    .visual{
      padding: 18px;
      display:flex;
      flex-direction: column;
      gap: 12px;
    }

    .visualCard{
      border-radius: 18px;
      border: 1px solid var(--border);
      background: var(--panel2);
      padding: 14px;
      position: relative;
      overflow:hidden;
    }

    .visualTitle{
      font-weight: 1000;
      font-size: 12px;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 10px;
    }

    .signRow{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: 12px;
    }

    .pedSignWrap{
      width: 150px;
      height: 150px;
      border-radius: 18px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(0,0,0,0.18);
      display:flex;
      align-items:center;
      justify-content:center;
      position: relative;
    }

    .warnTriangle{
      width: 90px;
      height: 90px;
      display:none;
      filter: drop-shadow(0 10px 18px rgba(0,0,0,0.45));
      animation: none;
      transform-origin: 50% 60%;
    }

    @keyframes warnPop{
      0%, 100% { transform: scale(1) rotate(-1deg); }
      50% { transform: scale(1.06) rotate(1deg); }
    }

    .hint{
      margin-top: 10px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
    }

    /* Level themes applied to root panel (they depend on the current detected VRU presence level) */
    .theme-low  { --glow: 0 0 0 10px rgba(34,197,94,0.14); }
    .theme-med  { --glow: 0 0 0 10px rgba(245,158,11,0.14); }
    .theme-high { --glow: 0 0 0 10px rgba(239,68,68,0.16); }

    .theme-low  .levelChip{ background: var(--g); }
    .theme-med  .levelChip{ background: var(--y); }
    .theme-high .levelChip{ background: var(--r); }

    .theme-low  .levelText{ color: var(--g); }
    .theme-med  .levelText{ color: var(--y); }
    .theme-high .levelText{ color: var(--r); }

    .theme-low  .dot{ background: var(--g); box-shadow: 0 0 0 4px rgba(34,197,94,0.18); }
    .theme-med  .dot{ background: var(--y); box-shadow: 0 0 0 4px rgba(245,158,11,0.18); }
    .theme-high .dot{ background: var(--r); box-shadow: 0 0 0 4px rgba(239,68,68,0.18); }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="topbar">
      <div class="title">VRU Presence Warning - Vehicle HMI</div>
      <div class="pill"><span class="dot" id="dot"></span><span id="status">Waiting for data...</span></div>
    </div>

    <div class="main">
      <!-- Left: status + data -->
      <div class="panel theme-low" id="panel">
        <div class="statusBanner">
          <div class="statusRow">
            <div class="statusLeft">
              <div class="levelChip" id="chip">!</div>
              <div>
                <div class="labelSmall">VRU presence level</div>
                <div class="levelText" id="level">--</div>
              </div>
            </div>
            <div class="countBox">
              <div class="count" id="vruCount">--</div>
              <div class="countSub">Estimated pedestrians</div>
            </div>
          </div>
        </div>

        <div class="metaGrid">
          <div class="card">
            <div class="k">Last measurement</div>
            <div class="v" id="ts">--</div>
          </div>
          <div class="card">
            <div class="k">Interval</div>
            <div class="v" id="interval">--</div>
          </div>
          <div class="card">
            <div class="k">Device</div>
            <div class="v" id="device">--</div>
          </div>
        </div>
      </div>

      <!-- Right panel: warning sign depending on the detected VRU presence level -->
      <div class="visualCard">
      <!--<div class="visualTitle">Status</div>-->

      <div class="signRow">
        <!-- Modify after "style" to change the size of the displayed warning sign -->
        <div class="pedSignWrap" aria-label="dynamic warning sign" style="width: 100%; height: 190px;">
          <!-- LOW: pedestrian.png -->
          <img id="imgLow" src="/static/pedestrian.png" alt="Pedestrian"
               style="display:none; max-width: 100%; max-height: 100%; object-fit: contain;" />

          <!-- MEDIUM: warning triangle (SVG) -->
          <svg class="warnTriangle" id="svgMed" viewBox="0 0 120 120" role="img" aria-label="Warning"
               style="display:none; width: 180px; height: 180px;">
            <path d="M60 10 L112 105 H8 Z" fill="#f59e0b" stroke="rgba(0,0,0,0.45)" stroke-width="6" />
            <path d="M60 30 L98 96 H22 Z" fill="#111827" opacity="0.12"/>
            <rect x="56" y="44" width="8" height="36" rx="4" fill="#111827"/>
            <circle cx="60" cy="92" r="5" fill="#111827"/>
          </svg>

          <!-- HIGH: danger.png -->
          <img id="imgHigh" src="/static/danger.png" alt="Danger"
               style="display:none; max-width: 100%; max-height: 100%; object-fit: contain;" />
        </div>
      </div>
    </div>
    </div>
  </div>

<script>
  // Forcing a robust transport; if your network allows websockets you can add it back.
  const socket = io({ transports: ["polling"] });

  const panel = document.getElementById("panel");
  const statusEl = document.getElementById("status");
  const connHint = document.getElementById("connHint");
  const warnTriangle = document.getElementById("warnTriangle");
  const imgLow = document.getElementById("imgLow");
  const svgMed = document.getElementById("svgMed");
  const imgHigh = document.getElementById("imgHigh");

  // socket.io functions
  function setTheme(level){
    panel.classList.remove("theme-low","theme-med","theme-high");
    if(level === "low") panel.classList.add("theme-low");
    else if(level === "medium") panel.classList.add("theme-med");
    else panel.classList.add("theme-high");
  }

  socket.on("connect", () => {
    console.log("[HMI] Socket connected", socket.id);
    statusEl.textContent = "Connected — waiting for MQTT…";
    connHint.textContent = "Socket: connected";
  });

  socket.on("disconnect", (reason) => {
    console.log("[HMI] Socket disconnected", reason);
    statusEl.textContent = "Disconnected — retrying…";
    connHint.textContent = "Socket: disconnected (" + reason + ")";
  });

  socket.on("update", d => {
    console.log("[HMI] update received:", d);

    // Expect keys from your Python payload:
    // VRU_presence_level, VRU_presence_level_color, VRU_count, string_ts, interval_seconds, device_id

    const lvl = (d.VRU_presence_level || "high").toLowerCase();
    setTheme(lvl);

    document.getElementById("level").textContent = lvl.toUpperCase();
    document.getElementById("vruCount").textContent = (d.VRU_count !== undefined) ? d.VRU_count : "--";
    document.getElementById("ts").textContent = d.string_ts || "--";
    document.getElementById("interval").textContent =
      (d.interval_seconds !== undefined && d.interval_seconds !== null) ? (d.interval_seconds + " s") : "--";
    document.getElementById("device").textContent = d.device_id || "--";

    // Show sign based on VRU detection level:
    // low -> pedestrian.png
    // medium -> triangle SVG (animated)
    // high -> danger.png (animated)
    imgLow.style.display = "none";
    svgMed.style.display = "none";
    imgHigh.style.display = "none";

    if (lvl === "low") {
      imgLow.style.display = "block";
    } else if (lvl === "medium") {
      svgMed.style.display = "block";
    } else { // high
      imgHigh.style.display = "block";
    }

    statusEl.textContent = "LIVE — updated";
    connHint.textContent = "Socket: receiving updates";
  });
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@socketio.on("connect")
def _connect():
    print("[HMI] Browser connected!")
    global last_payload
    if last_payload is not None:
        print("[HMI] Sending last payload to newly connected client")
        socketio.emit("update", last_payload)


@socketio.on("disconnect")
def _disconnect():
    print("[HMI] Browser disconnected!")

if __name__ == "__main__":
    start_mqtt()
    print(f"[HMI] Web-based HMI active on http://{args.web_host}:{args.web_port}")
    socketio.run(app, host=args.web_host, port=args.web_port)
