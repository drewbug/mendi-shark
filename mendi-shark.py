#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pyserial>=3.5",
#     "psutil",
# ]
# ///
"""mendi-shark: BLE sniffer for MENDI neurofeedback headband.

Captures BLE traffic, decodes ATT/GATT protocol, and displays
Mendi protobuf values (fNIRS frames, sensor, calibration) in real-time.
"""

import sys
import os
import time
import argparse

from SnifferAPI import Sniffer, Devices, UART
from SnifferAPI.Types import *

SERIAL_PORT = "/dev/ttyACM0"
TARGET_NAME = "MENDI"

ADV_TYPES = {
    0: "ADV_IND",
    1: "ADV_DIRECT_IND",
    2: "ADV_NONCONN_IND",
    3: "SCAN_REQ",
    4: "SCAN_RSP",
    5: "CONNECT_IND",
    6: "ADV_SCAN_IND",
    7: "ADV_EXT_IND",
}

# ── ATT opcodes ──────────────────────────────────────────────────────────────

ATT_READ_BY_TYPE_RSP = 0x09
ATT_READ_REQ         = 0x0A
ATT_READ_RSP         = 0x0B
ATT_WRITE_REQ        = 0x12
ATT_WRITE_CMD        = 0x52
ATT_HANDLE_VALUE_NTF = 0x1B
ATT_HANDLE_VALUE_IND = 0x1D

ATT_NAMES = {
    0x01: "ERR", 0x02: "MTU_REQ", 0x03: "MTU_RSP",
    0x04: "FIND_INFO_REQ", 0x05: "FIND_INFO_RSP",
    0x08: "RD_TYPE_REQ", 0x09: "RD_TYPE_RSP",
    0x0A: "READ_REQ", 0x0B: "READ_RSP",
    0x10: "RD_GRP_REQ", 0x11: "RD_GRP_RSP",
    0x12: "WRITE_REQ", 0x13: "WRITE_RSP",
    0x1B: "NOTIFY", 0x1D: "INDICATE", 0x1E: "CONFIRM",
    0x52: "WRITE_CMD",
}

# ── Mendi BLE protocol ───────────────────────────────────────────────────────
# Base UUID: fc3eXXXX-c6c4-49e6-922a-6e551c455af5
# In LE 128-bit byte order:
#   f5 5a 45 1c 55 6e 2a 92 e6 49 c4 c6 [XX XX] 3e fc

MENDI_UUID_LE_PREFIX = bytes([
    0xF5, 0x5A, 0x45, 0x1C, 0x55, 0x6E, 0x2A, 0x92,
    0xE6, 0x49, 0xC4, 0xC6,
])

MENDI_CHAR_NAMES = {
    0xABB0: "Service",
    0xABB1: "Frame",
    0xABB2: "Sensor",
    0xABB3: "IMU",
    0xABB4: "Battery",
    0xABB5: "Diagnostic",
    0xABB6: "Calibration",
}

STANDARD_CHAR_NAMES = {
    0x2A00: "DeviceName",
    0x2A01: "Appearance",
    0x2A26: "FW_Rev",
    0x2A27: "HW_Rev",
    0x2A29: "Manufacturer",
}

# Protobuf field maps (field_number → label)
FRAME_FIELDS = {
    1: "ACC_X", 2: "ACC_Y", 3: "ACC_Z",
    4: "ANG_X", 5: "ANG_Y", 6: "ANG_Z", 7: "TEMP",
    8: "IR_L", 9: "IR_R", 10: "IR_P",
    11: "RED_L", 12: "RED_R", 13: "RED_P",
    14: "AMB_L", 15: "AMB_R", 16: "AMB_P",
}


# ── Protobuf decoder ─────────────────────────────────────────────────────────

def _varint(data, pos):
    """Decode a protobuf varint, return (value, new_pos)."""
    val = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, pos
        shift += 7
    return val, pos


def decode_proto(data):
    """Decode a flat protobuf message → {field_number: value}."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = _varint(data, pos)
        wire = tag & 7; fnum = tag >> 3
        if fnum == 0:
            break
        if wire == 0:  # varint
            val, pos = _varint(data, pos)
            fields[fnum] = val
        elif wire == 2:  # length-delimited
            length, pos = _varint(data, pos)
            fields[fnum] = data[pos:pos + length]
            pos += length
        elif wire == 5:  # 32-bit fixed
            fields[fnum] = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
        elif wire == 1:  # 64-bit fixed
            fields[fnum] = int.from_bytes(data[pos:pos + 8], "little")
            pos += 8
        else:
            break
    return fields


def _s32(v):
    """Unsigned varint → signed int32."""
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


# ── L2CAP reassembly ─────────────────────────────────────────────────────────

class L2CAPReassembler:
    """Reassembles fragmented L2CAP PDUs from BLE data channel packets."""

    def __init__(self):
        self._buf = [bytearray(), bytearray()]   # per direction
        self._need = [0, 0]
        self._cid = [0, 0]

    def feed(self, direction, llid, data):
        """Feed LL payload bytes. Returns (cid, sdu) when complete, else None."""
        d = 1 if direction else 0
        if llid == 2:  # L2CAP start
            if len(data) < 4:
                return None
            self._need[d] = data[0] | (data[1] << 8)
            self._cid[d] = data[2] | (data[3] << 8)
            self._buf[d] = bytearray(data[4:])
        elif llid == 1:  # continuation
            self._buf[d].extend(data)
        else:
            return None
        if self._need[d] > 0 and len(self._buf[d]) >= self._need[d]:
            out = bytes(self._buf[d][:self._need[d]])
            self._buf[d].clear()
            self._need[d] = 0
            return (self._cid[d], out)
        return None


# ── GATT handle map ──────────────────────────────────────────────────────────

class HandleMap:
    """Learns ATT handle → characteristic mappings from GATT discovery."""

    def __init__(self):
        self.handles = {}  # value_handle → (name_str, short_code_int_or_None)
        self._pending_read = None

    def on_att(self, att_pdu):
        """Process a complete ATT PDU. Returns list of discovered (handle, name)
        pairs, or ("READ_RSP", handle, value) tuple, or None."""
        if len(att_pdu) < 1:
            return None
        op = att_pdu[0]

        # Learn characteristic declarations from Read By Type Response
        if op == ATT_READ_BY_TYPE_RSP and len(att_pdu) >= 4:
            return self._parse_read_by_type_rsp(att_pdu)

        # Track Read Request handle so we can label the response
        if op == ATT_READ_REQ and len(att_pdu) >= 3:
            self._pending_read = att_pdu[1] | (att_pdu[2] << 8)

        if op == ATT_READ_RSP and self._pending_read is not None:
            h = self._pending_read
            self._pending_read = None
            return ("READ_RSP", h, att_pdu[1:])

        return None

    def _parse_read_by_type_rsp(self, pdu):
        entry_len = pdu[1]
        data = pdu[2:]
        found = []
        i = 0
        while i + entry_len <= len(data):
            entry = data[i:i + entry_len]
            i += entry_len
            if entry_len < 7:
                continue
            # Characteristic declaration: properties(1) + value_handle(2) + uuid
            val_handle = entry[3] | (entry[4] << 8)
            uuid_bytes = entry[5:]

            if len(uuid_bytes) == 2:
                uuid16 = uuid_bytes[0] | (uuid_bytes[1] << 8)
                name = STANDARD_CHAR_NAMES.get(uuid16, f"0x{uuid16:04X}")
                self.handles[val_handle] = (name, uuid16)
                found.append((val_handle, name))

            elif len(uuid_bytes) == 16:
                if (uuid_bytes[:12] == MENDI_UUID_LE_PREFIX
                        and uuid_bytes[14] == 0x3E and uuid_bytes[15] == 0xFC):
                    short = uuid_bytes[12] | (uuid_bytes[13] << 8)
                    name = MENDI_CHAR_NAMES.get(short, f"0x{short:04X}")
                    self.handles[val_handle] = (name, short)
                    found.append((val_handle, name))

        return found if found else None

    def lookup(self, handle):
        return self.handles.get(handle)


# ── Display formatters ────────────────────────────────────────────────────────

def fmt_frame(data):
    f = decode_proto(data)
    g = lambda n: _s32(f.get(n, 0))
    return (f"IR:{g(8)}/{g(9)}/{g(10)} "
            f"RED:{g(11)}/{g(12)}/{g(13)} "
            f"AMB:{g(14)}/{g(15)}/{g(16)} "
            f"ACC:{g(1)}/{g(2)}/{g(3)} "
            f"ANG:{g(4)}/{g(5)}/{g(6)} "
            f"T:{g(7)}")


def fmt_sensor(data):
    f = decode_proto(data)
    rw = "R" if f.get(1, 0) else "W"
    return f"{rw} addr=0x{f.get(2, 0):02x} data=0x{f.get(3, 0):x}"


def fmt_battery(data):
    f = decode_proto(data)
    return f"{f.get(1, 0)}mV chrg={f.get(2, 0)} usb={f.get(3, 0)}"


def fmt_calibration(data):
    f = decode_proto(data)
    return (f"off={_s32(f.get(1, 0))}/{_s32(f.get(2, 0))}/{_s32(f.get(3, 0))} "
            f"en={f.get(4, 0)} lp={f.get(5, 0)}")


def fmt_diagnostic(data):
    f = decode_proto(data)
    parts = []
    for k, v in sorted(f.items()):
        if isinstance(v, (bytes, bytearray)):
            sub = decode_proto(v)
            parts.append(f"ADC({sub.get(1, 0)}mV chrg={sub.get(2, 0)} usb={sub.get(3, 0)})")
        elif k == 2:
            parts.append(f"imu_ok={v}")
        elif k == 3:
            parts.append(f"sensor_ok={v}")
        else:
            parts.append(f"f{k}={v}")
    return " ".join(parts) or "(empty)"


FORMATTERS = {
    0xABB1: ("Frame", fmt_frame),
    0xABB2: ("Sensor", fmt_sensor),
    0xABB3: ("IMU", fmt_sensor),       # same register-level format
    0xABB4: ("Battery", fmt_battery),
    0xABB5: ("Diagnostic", fmt_diagnostic),
    0xABB6: ("Calibration", fmt_calibration),
}


def decode_value(handle, data, hmap):
    """Decode an ATT value payload for display."""
    info = hmap.lookup(handle)
    if info is None:
        return f"h:0x{handle:04x} {data.hex()}"

    name, code = info

    if code in FORMATTERS:
        label, fn = FORMATTERS[code]
        try:
            return f"{label}  {fn(data)}"
        except Exception:
            return f"{label}  {data.hex()}"

    # Standard string characteristics (FW_Rev, HW_Rev, etc.)
    if isinstance(code, int) and code < 0x3000:
        try:
            text = data.decode("utf-8")
            if text.isprintable():
                return f'{name}  "{text}"'
        except Exception:
            pass

    return f"{name}  {data.hex()}"


# ── Helpers ───────────────────────────────────────────────────────────────────

def format_addr(address):
    """Format a 7-byte address list (6 bytes + type) as a string."""
    if not address or len(address) < 6:
        return "??:??:??:??:??:??"
    addr_str = ":".join(f"{b:02x}" for b in address[:6])
    addr_type = "random" if (len(address) > 6 and address[6]) else "public"
    return f"{addr_str} ({addr_type})"


def find_baudrate(port):
    """Detect the sniffer's baud rate."""
    rates = UART.find_sniffer_baudrates(port)
    if rates is None:
        print(f"Could not detect sniffer on {port}")
        sys.exit(1)
    return rates["default"]


def scan_for_device(sniffer, target_name, timeout=30):
    """Scan for a device whose name contains target_name."""
    print(f'Scanning for "{target_name}"...', flush=True)
    sniffer.scan(True, True, False)

    seen = set()
    deadline = time.time() + timeout

    while time.time() < deadline:
        devices = sniffer.getDevices().asList()
        for dev in devices:
            addr_key = tuple(dev.address)
            if addr_key not in seen:
                seen.add(addr_key)
                print(f"  {format_addr(dev.address)}  {dev.name}  {dev.RSSI}dBm", flush=True)

            if target_name.lower() in dev.name.lower():
                print(f'\nFound: {dev.name} at {format_addr(dev.address)}', flush=True)
                return dev

        time.sleep(0.1)

    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="mendi-shark: BLE sniffer for MENDI devices")
    parser.add_argument("-p", "--port", default=SERIAL_PORT,
                        help=f"Serial port (default: {SERIAL_PORT})")
    parser.add_argument("-n", "--name", default=TARGET_NAME,
                        help=f"Device name to search for (default: {TARGET_NAME})")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Scan timeout in seconds (default: 30)")
    parser.add_argument("--scan-only", action="store_true",
                        help="Only scan, don't follow")
    parser.add_argument("--adv-only", action="store_true",
                        help="Only capture advertising packets (don't follow into connections)")
    args = parser.parse_args()

    baudrate = find_baudrate(args.port)
    print(f"mendi-shark: {args.port} @ {baudrate} baud\n", flush=True)

    sniffer = Sniffer.Sniffer(args.port, baudrate)
    sniffer.start()
    sniffer.setAdvHopSequence([37, 38, 39])
    sniffer.getFirmwareVersion()
    sniffer.getTimestamp()

    try:
        device = scan_for_device(sniffer, args.name, args.timeout)
        if not device:
            print(f'"{args.name}" not found within {args.timeout}s.')
            return

        if args.scan_only:
            return

        print(f"\nFollowing {device.name}...", flush=True)
        sniffer.follow(device, followOnlyAdvertisements=args.adv_only)
        print("Press Ctrl+C to stop\n", flush=True)

        reassembler = L2CAPReassembler()
        hmap = HandleMap()
        pkt_num = 0

        while True:
            packets = sniffer.getPackets()
            for packet in packets:
                if not packet.valid or not packet.blePacket:
                    continue
                if not packet.OK:
                    continue

                bp = packet.blePacket
                pkt_num += 1

                # Advertising packets
                if bp.type == PACKET_TYPE_ADVERTISING:
                    if bp.advType == 5:  # CONNECT_IND
                        print(f"[{pkt_num}] *** CONNECTION ***", flush=True)
                    continue

                # Data packets — only L2CAP start/continuation
                if bp.llid not in (1, 2):
                    continue

                payload = bytes(bp.payload[:bp.length])
                result = reassembler.feed(packet.direction, bp.llid, payload)
                if result is None:
                    continue

                cid, att_pdu = result
                if cid != 0x0004 or len(att_pdu) < 1:
                    continue  # not ATT

                opcode = att_pdu[0]

                # Learn GATT handle mappings from discovery
                discovery = hmap.on_att(att_pdu)
                if isinstance(discovery, list):
                    for val_handle, name in discovery:
                        print(f"  [GATT] {name} -> handle 0x{val_handle:04x}",
                              flush=True)

                # Notifications (device -> phone)
                if opcode == ATT_HANDLE_VALUE_NTF and len(att_pdu) >= 3:
                    handle = att_pdu[1] | (att_pdu[2] << 8)
                    value = att_pdu[3:]
                    if value:
                        print(f"[{pkt_num}] <- {decode_value(handle, value, hmap)}",
                              flush=True)

                # Indications (device -> phone)
                elif opcode == ATT_HANDLE_VALUE_IND and len(att_pdu) >= 3:
                    handle = att_pdu[1] | (att_pdu[2] << 8)
                    value = att_pdu[3:]
                    if value:
                        print(f"[{pkt_num}] <- IND {decode_value(handle, value, hmap)}",
                              flush=True)

                # Writes (phone -> device)
                elif opcode in (ATT_WRITE_REQ, ATT_WRITE_CMD) and len(att_pdu) >= 3:
                    handle = att_pdu[1] | (att_pdu[2] << 8)
                    value = att_pdu[3:]
                    if value:
                        tag = "WRITE" if opcode == ATT_WRITE_REQ else "WCMD"
                        print(f"[{pkt_num}] -> {tag} {decode_value(handle, value, hmap)}",
                              flush=True)

                # Read responses (device -> phone)
                elif (isinstance(discovery, tuple)
                      and discovery[0] == "READ_RSP"):
                    _, rh, rv = discovery
                    if rv:
                        print(f"[{pkt_num}] <- READ {decode_value(rh, rv, hmap)}",
                              flush=True)

            if not packets:
                time.sleep(0.01)

    except KeyboardInterrupt:
        print(f"\nDone.", flush=True)
    finally:
        sniffer.doExit()


if __name__ == "__main__":
    main()
