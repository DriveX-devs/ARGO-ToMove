#!/usr/bin/env python3

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
# This import is to let us run this code on older Python versions
from typing import Optional

import gps
import paho.mqtt.client as mqtt

# Patch for "gps" library issue with Python >3.9 (without this, the code will terminate with an error due to an unsupported "encoding" arg)
_original_loads = json.loads
def _patched_loads(s, *args, **kwargs):
    kwargs.pop("encoding", None) # remove unsupported "encoding" arg
    return _original_loads(s, *args, **kwargs)
json.loads = _patched_loads

DEFAULT_GPSD_HOST = "localhost"
DEFAULT_GPSD_PORT = 2947 # Default gpsd port
DEFAULT_BROKER_HOST = "127.0.0.1"
DEFAULT_BROKER_PORT = 1883
DEFAULT_TOPIC = "sample-topic"
DEFAULT_MQTT_USER = "sample-user"
DEFAULT_DEVICE_ID = "sample-device-id"
DEFAULT_INTERVAL = 0.5 # Periodicity at which the position should be sent to the backend - default: 500 ms

def build_mqtt_client(device_id: str, user: str, password: str) -> mqtt.Client:
    # Create and configure a Paho MQTT client

    client = mqtt.Client(client_id=device_id)
    client.username_pw_set(user, password)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT broker (rc=0)")
        else:
            print(f"MQTT connection failed with return code {rc}")

    def on_publish(client, userdata, mid):
        print(f"Message published (mid={mid})")

    def on_disconnect(client, userdata, rc):
        if rc != 0:
            print(f"Unexpected MQTT disconnection (rc={rc}). Will try to auto-reconnect.")

    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_disconnect = on_disconnect

    return client


def connect_mqtt(client: mqtt.Client, host: str, port: int) -> None:
    # Connect the MQTT client and start the background network loop

    print(f"Connecting to MQTT broker at {host}:{port}")
    client.connect(host, port, keepalive=60)
    client.loop_start()

# GNSS receiver interface

def open_gpsd(host: str = DEFAULT_GPSD_HOST,
              port: int  = DEFAULT_GPSD_PORT) -> gps.gps:
    # Connect to gpsd
    print(f"Connecting to gpsd at {host}:{port}", host, port)
    session = gps.gps(host=host, port=port, mode=gps.WATCH_ENABLE | gps.WATCH_NEWSTYLE)
    return session

# Function to get the latest positioning information from the GNSS receiver
# The while loop flushes the gpsd buffer to get the latest TPV report
def read_fix(session: gps.gps) -> Optional[dict]:
    last_tpv = None

    while True:
        try:
            report = session.next()
        except StopIteration:
            print("gpsd stream ended unexpectedly.")
            return None

        if report["class"] == "TPV":
            last_tpv = report

        if not session.waiting() and last_tpv is not None:
            break

    fix_mode = getattr(last_tpv,"mode",gps.MODE_NO_FIX)

    if fix_mode < gps.MODE_2D:
        return None

    if hasattr(last_tpv, "time") and last_tpv.time:
        try:
            ts = datetime.fromisoformat(last_tpv.time.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(tz=timezone.utc)
    else:
        ts = datetime.now(tz=timezone.utc)

    return {
        "timestamp": int(ts.timestamp()),
        "latitude": getattr(last_tpv, "lat",   float("nan")),
        "longitude": getattr(last_tpv, "lon",   float("nan")),
        "speed": getattr(last_tpv, "speed", float("nan")),
        "heading": getattr(last_tpv, "track", float("nan")),
    }

def run(args: argparse.Namespace) -> None:
    # MQTT client configuration
    client = build_mqtt_client(args.mqtt_device_id, args.user, args.password)
    connect_mqtt(client, args.broker_host, args.broker_port)

    # gpsd interface configuration
    gps_session = open_gpsd(args.gpsd_host, args.gpsd_port)

    try:
        while True:
            fix = read_fix(gps_session)
            if fix is None:
                time.sleep(0.1) # In case the fix is not available yet, retry again in a short time span (100 ms)
                continue

            payload: dict = {
                "device_id": args.mqtt_device_id,
                "timestamp": fix["timestamp"],
                "latitude": fix["latitude"],
                "longitude": fix["longitude"],
                "speed": fix["speed"],
                "heading": fix["heading"],
            }

            json_str = json.dumps(payload)
            result = client.publish(args.topic, json_str, qos=1)

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                print("Published:", json_str)
            else:
                print("Publish failed. Error code:", result.rc)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("Interrupted by user: shutting down!")
    finally:
        client.loop_stop()
        client.disconnect()
        gps_session.close()
        print("Clean shutdown complete.")

# Command line argument management and parsing
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AuToMove Nav Sender for DriveX OBU: retrieves GNSS data from gpsd and publishes it to an MQTT broker in a JSON format",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # MQTT broker
    mqtt_group = parser.add_argument_group("MQTT broker")
    mqtt_group.add_argument("--broker-host", default=DEFAULT_BROKER_HOST, help="MQTT broker hostname or IP")
    mqtt_group.add_argument("--broker-port", default=DEFAULT_BROKER_PORT, type=int, help="MQTT broker port")
    mqtt_group.add_argument("--topic", default=DEFAULT_TOPIC, help="MQTT topic to publish on")
    mqtt_group.add_argument("--user", default=DEFAULT_MQTT_USER, help="MQTT username")
    mqtt_group.add_argument("--password", required=True, help="MQTT password (required, no default)")
    mqtt_group.add_argument("--mqtt-device-id", default=DEFAULT_DEVICE_ID, help="MQTT client / device identifier")
    parser.add_argument("--interval", default=DEFAULT_INTERVAL, type=float, help="Seconds between MQTT publishes")

    # gpsd
    gps_group = parser.add_argument_group("gpsd")
    gps_group.add_argument("--gpsd-host", default=DEFAULT_GPSD_HOST, help="gpsd hostname")
    gps_group.add_argument("--gpsd-port", default=DEFAULT_GPSD_PORT, type=int, help="gpsd port")

    return parser.parse_args()

# main function (entry point)
if __name__ == "__main__":
    args = parse_args()

    run(args)
