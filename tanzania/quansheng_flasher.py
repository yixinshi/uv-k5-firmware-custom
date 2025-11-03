#!/usr/bin/env python3
"""
flash_quansheng.py

Python reimplementation of the Quansheng webflasher logic (from provided JS source).
Usage:
    python flash_quansheng.py --port /dev/ttyUSB0 firmware.bin
    python flash_quansheng.py --port COM3 firmware.bin --debug
"""

import argparse
import logging
import serial
import time
import sys
from typing import Optional

# ---------- CRC table & functions (crc16-ccitt) ----------
Crc16Tab = [
0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935,
4657, 528, 12915, 8786, 21173, 17044, 29431, 25302, 37689, 33560, 45947, 41818, 54205, 50076, 62463, 58334,
9314, 13379, 1056, 5121, 25830, 29895, 17572, 21637, 42346, 46411, 34088, 38153, 58862, 62927, 50604, 54669,
13907, 9842, 5649, 1584, 30423, 26358, 22165, 18100, 46939, 42874, 38681, 34616, 63455, 59390, 55197, 51132,
18628, 22757, 26758, 30887, 2112, 6241, 10242, 14371, 51660, 55789, 59790, 63919, 35144, 39273, 43274, 47403,
23285, 19156, 31415, 27286, 6769, 2640, 14899, 10770, 56317, 52188, 64447, 60318, 39801, 35672, 47931, 43802,
27814, 31879, 19684, 23749, 11298, 15363, 3168, 7233, 60846, 64911, 52716, 56781, 44330, 48395, 36200, 40265,
32407, 28342, 24277, 20212, 15891, 11826, 7761, 3696, 65439, 61374, 57309, 53244, 48923, 44858, 40793, 36728,
37256, 33193, 45514, 41451, 53516, 49453, 61774, 57711, 4224, 161, 12482, 8419, 20484, 16421, 28742, 24679,
33721, 37784, 41979, 46042, 49981, 54044, 58239, 62302, 689, 4752, 8947, 13010, 16949, 21012, 25207, 29270,
46570, 42443, 38312, 34185, 62830, 58703, 54572, 50445, 13538, 9411, 5280, 1153, 29798, 25671, 21540, 17413,
42971, 47098, 34713, 38840, 59231, 63358, 50973, 55100, 9939, 14066, 1681, 5808, 26199, 30326, 17941, 22068,
55628, 51565, 63758, 59695, 39368, 35305, 47498, 43435, 22596, 18533, 30726, 26663, 6336, 2273, 14466, 10403,
52093, 56156, 60223, 64286, 35833, 39896, 43963, 48026, 19061, 23124, 27191, 31254, 2801, 6864, 10931, 14994,
64814, 60687, 56684, 52557, 48554, 44427, 40424, 36297, 31782, 27655, 23652, 19525, 15522, 11395, 7392, 3265,
61215, 65342, 53085, 57212, 44955, 49082, 36825, 40952, 28183, 32310, 20053, 24180, 11923, 16050, 3793, 7920
]


def crc16_ccitt(data: bytes) -> int:
    """Return 16-bit CRC (integer) using the table from JS"""
    i2 = 0
    for b in data:
        out = Crc16Tab[((i2 >> 8) ^ b) & 0xff]
        i2 = out ^ ((i2 << 8) & 0xffffffff)
    return i2 & 0xffff


def crc16_ccitt_le_bytes(data: bytes) -> bytes:
    crc = crc16_ccitt(data)
    return bytes([crc & 0xff, (crc >> 8) & 0xff])


# ---------- firmware XOR (fwpack.js) ----------
_FW_XOR_ARRAY = bytes([
    0x47, 0x22, 0xc0, 0x52, 0x5d, 0x57, 0x48, 0x94, 0xb1, 0x60, 0x60, 0xdb, 0x6f, 0xe3, 0x4c, 0x7c,
    0xd8, 0x4a, 0xd6, 0x8b, 0x30, 0xec, 0x25, 0xe0, 0x4c, 0xd9, 0x00, 0x7f, 0xbf, 0xe3, 0x54, 0x05,
    0xe9, 0x3a, 0x97, 0x6b, 0xb0, 0x6e, 0x0c, 0xfb, 0xb1, 0x1a, 0xe2, 0xc9, 0xc1, 0x56, 0x47, 0xe9,
    0xba, 0xf1, 0x42, 0xb6, 0x67, 0x5f, 0x0f, 0x96, 0xf7, 0xc9, 0x3c, 0x84, 0x1b, 0x26, 0xe1, 0x4e,
    0x3b, 0x6f, 0x66, 0xe6, 0xa0, 0x6a, 0xb0, 0xbf, 0xc6, 0xa5, 0x70, 0x3a, 0xba, 0x18, 0x9e, 0x27,
    0x1a, 0x53, 0x5b, 0x71, 0xb1, 0x94, 0x1e, 0x18, 0xf2, 0xd6, 0x81, 0x02, 0x22, 0xfd, 0x5a, 0x28,
    0x91, 0xdb, 0xba, 0x5d, 0x64, 0xc6, 0xfe, 0x86, 0x83, 0x9c, 0x50, 0x1c, 0x73, 0x03, 0x11, 0xd6,
    0xaf, 0x30, 0xf4, 0x2c, 0x77, 0xb2, 0x7d, 0xbb, 0x3f, 0x29, 0x28, 0x57, 0x22, 0xd6, 0x92, 0x8b
])


def firmware_xor(data: bytes) -> bytes:
    arr = bytearray(data)
    L = len(_FW_XOR_ARRAY)
    for i in range(len(arr)):
        arr[i] ^= _FW_XOR_ARRAY[i % L]
    return bytes(arr)


# ---------- helper functions from JS: xor for packet-level obfuscation ----------
_K5_XOR_ARRAY = bytes([
    0x16, 0x6c, 0x14, 0xe6, 0x2e, 0x91, 0x0d, 0x40,
    0x21, 0x35, 0xd5, 0x40, 0x13, 0x03, 0xe9, 0x80
])


def k5_xor(data: bytes) -> bytes:
    arr = bytearray(data)
    L = len(_K5_XOR_ARRAY)
    for i in range(len(arr)):
        arr[i] ^= _K5_XOR_ARRAY[i % L]
    return bytes(arr)


# ---------- CRC-XMODEM ----------
def crc16xmodem(data: bytes, crc: int = 0) -> int:
    poly = 0x1021
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
    return crc & 0xffff


# ---------- packetize / unpacketize ----------
def packetize(data: bytes) -> bytes:
    header = bytes([0xAB, 0xCD])
    length = bytes([len(data) & 0xff, (len(data) >> 8) & 0xff])  # little-endian length like JS
    crc = crc16xmodem(data)
    crc_bytes = bytes([crc & 0xff, (crc >> 8) & 0xff])  # little-endian
    unobfuscated = data + crc_bytes
    obfuscated = k5_xor(unobfuscated)
    footer = bytes([0xDC, 0xBA])
    return header + length + obfuscated + footer


def unpacketize(packet: bytes) -> bytes:
    if len(packet) < 8:
        raise ValueError("Packet too short")
    length = packet[2] + (packet[3] << 8)
    obfuscated = packet[4: len(packet) - 4]
    if len(obfuscated) != length:
        raise ValueError("Packet length mismatch")
    return k5_xor(obfuscated)  # returns data+crc


# ---------- global state ----------
rawVersion: Optional[bytes] = None
rawFirmware: Optional[bytes] = None

# ---------- firmware pack/unpack (mirror JS) ----------
def unpack(encoded_firmware: bytes) -> Optional[bytes]:
    """
    Validate CRC (crc16-ccitt little-endian), XOR-decode, strip 16-byte version block at 0x2000.
    Returns decoded firmware (with version block removed) or None on error.
    """
    global rawVersion
    if len(encoded_firmware) < 2:
        logging.error("Encoded firmware too small")
        return None

    expected_crc_bytes = encoded_firmware[-2:]
    calc_crc_bytes = crc16_ccitt_le_bytes(encoded_firmware[:-2])
    if calc_crc_bytes != expected_crc_bytes:
        logging.error("WARNING: CRC CHECK FAILED! FIRMWARE NOT VALID!")
        return None
    logging.info("CRC check passed...")

    decoded = firmware_xor(encoded_firmware[:-2])
    versionInfoOffset = 0x2000
    versionInfoLength = 16
    if len(decoded) < versionInfoOffset + versionInfoLength:
        logging.error("Decoded firmware too small or missing version info")
        return None
    # Remove the version block from the firmware image
    result = decoded[:versionInfoOffset] + decoded[versionInfoOffset + versionInfoLength:]
    rawVersion = decoded[versionInfoOffset:versionInfoOffset + versionInfoLength]
    return result


def pack(decoded_firmware: bytes) -> bytes:
    """
    Insert rawVersion at 0x2000, XOR-encode and append crc16-ccitt (LE).
    """
    if rawVersion is None:
        raise RuntimeError("rawVersion not set")
    versionInfoOffset = 0x2000
    versionInfoLength = 16
    # Assemble with version block
    pre = decoded_firmware[:versionInfoOffset]
    post = decoded_firmware[versionInfoOffset:]
    result = pre + rawVersion + post
    encoded = firmware_xor(result)
    crc = crc16_ccitt_le_bytes(encoded)
    return encoded + crc


# ---------- serial I/O helpers ----------
def open_serial(port: str, baud: int = 38400, timeout: float = 0.1) -> serial.Serial:
    ser = serial.Serial(port=port, baudrate=baud, timeout=timeout)
    logging.info("Opened serial port %s @ %d", port, baud)
    return ser


def read_packet(ser: serial.Serial, expected_first_byte: int, timeout_ms: int = 1000) -> bytes:
    """
    Read packets from serial until a packet whose deobfuscated data[0] == expected_first_byte is found,
    or until timeout (ms).
    Packet format: [0xAB,0xCD, len_lo, len_hi, obfuscated(payload+crc), 0xDC,0xBA]
    Returns deobfuscated payload+crc (bytes).
    Raises TimeoutError on timeout, ValueError on malformed packet.
    """
    deadline = time.monotonic() + (timeout_ms / 1000.0)
    buffer = bytearray()

    while True:
        # timeout check
        if time.monotonic() > deadline:
            raise TimeoutError("Timeout: Packet not received within specified time.")

        # read any available bytes (blocking small amount controlled by serial timeout)
        chunk = ser.read(max(1, ser.in_waiting or 1))
        if chunk:
            buffer.extend(chunk)
            logging.debug("Read %d bytes, buffer=%d", len(chunk), len(buffer))
        else:
            # no data currently — loop and wait until deadline
            continue

        # Strip leading bytes until we find 0xAB
        while len(buffer) > 0 and buffer[0] != 0xAB:
            buffer.pop(0)

        # if we have at least header+length fields
        while len(buffer) >= 4 and buffer[0] == 0xAB and buffer[1] == 0xCD:
            payload_len = buffer[2] + (buffer[3] << 8)
            total_len = payload_len + 8  # header (2) + length (2) + payload_len + footer (2) + ??? (JS used +8)
            # total_len explanation: JS used payloadLength + 8 (header(2)+len(2)+footer(2)+crc(2) included in payload_len)
            if len(buffer) < total_len:
                break  # wait for more data

            packet = bytes(buffer[:total_len])
            # check footer positions
            if packet[-2] != 0xDC or packet[-1] != 0xBA:
                # invalid packet: discard first byte and continue scanning
                buffer.pop(0)
                logging.debug("Invalid footer, discarding a byte and continuing")
                continue

            # extract and process
            try:
                deob = unpacketize(packet)  # returns payload+crc (but xor reversed)
            except Exception as e:
                logging.exception("Failed to unpacketize: %s", e)
                buffer.pop(0)
                continue

            # remove consumed bytes
            del buffer[:total_len]

            if len(deob) == 0:
                logging.debug("Empty deobfuscated payload")
                continue

            if deob[0] != expected_first_byte:
                logging.debug("Unexpected packet (first byte %02x), continuing", deob[0])
                # continue reading; do not return this packet
                continue

            # found expected
            return deob

    # never reached


def send_packet(ser: serial.Serial, data: bytes):
    pkt = packetize(data)
    logging.debug("Sending packet: %s", pkt.hex())
    ser.write(pkt)
    ser.flush()


# ---------- flash-related functions ----------
def flash_init(ser: serial.Serial) -> bytes:
    """
    Send version info packet (0x30 ...) containing rawVersion and wait for response (0x18).
    Returns the response bytes (deobfuscated payload+crc) if 0x18 received.
    """
    global rawVersion
    if rawVersion is None:
        raise RuntimeError("rawVersion not set")

    # data structure per JS: [0x30, 0x5, rawVersion.length, 0x0, ...rawVersion]
    data = bytes([0x30, 0x05, len(rawVersion), 0x00]) + rawVersion
    logging.info("Sending version request")
    send_packet(ser, data)
    # wait for 0x18 response (use a slightly longer timeout)
    resp = read_packet(ser, 0x18, timeout_ms=2000)
    logging.debug("Version response raw: %s", resp.hex())
    if resp[0] == 0x18:
        return resp
    raise RuntimeError("Unexpected response to version request")


def flash_checkVersion(dataPacket: bytes, versionFromFirmware: bytes) -> bool:
    """
    Validate bootloader type vs firmware first byte as in JS.
    Prints bootloader version from dataPacket[0x14:0x14+7] (if present).
    """
    try:
        if len(dataPacket) >= 0x14 + 7:
            boot_ver_bytes = dataPacket[0x14:0x14 + 7]
            # decode as ASCII if printable
            try:
                boot_str = boot_ver_bytes.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
                logging.info("Bootloader version: %s", boot_str)
            except Exception:
                logging.info("Bootloader version (raw): %s", boot_ver_bytes.hex())
    except Exception:
        pass

    # wildcard '*' (0x2a) allowed
    if versionFromFirmware[0] == 0x2A:
        return True
    if len(dataPacket) > 0x14:
        return dataPacket[0x14] == versionFromFirmware[0]
    return False


def flash_generateCommand(data_block: bytes, address: int, totalSize: int) -> bytes:
    """
    Create flash command packet data from a 0x100 block, address, and total size.
    Returns the command payload (which will then be packetized).
    """
    if len(data_block) < 0x100:
        data_block = data_block + bytes(0x100 - len(data_block))
    if len(data_block) != 0x100:
        raise ValueError("Block length after padding is not 0x100")

    address_msb = (address & 0xff00) >> 8
    address_lsb = address & 0xff
    address_final = (totalSize + 0xff) & ~0xff
    if address_final > 0xf000:
        raise ValueError("Total size is too large")
    address_final_msb = (address_final & 0xff00) >> 8
    address_final_lsb = 0x0

    length_msb = 0x01
    length_lsb = 0x00

    header_prefix = bytes([0x19, 0x5, 0xC, 0x1, 0x8A, 0x8D, 0x9F, 0x1D])
    return header_prefix + bytes([address_msb, address_lsb, address_final_msb, address_final_lsb, length_msb, length_lsb, 0x0, 0x0]) + data_block


def flash_flashFirmware(ser: serial.Serial, firmware: bytes):
    """
    Main flashing loop: write firmware in 0x100 blocks, wait for 0x1A ack after each block.
    """
    if len(firmware) > 0xEFFF:
        raise ValueError("Firmware too large (safety check)")
    logging.info("Flashing... 0%%")
    total = len(firmware)
    i = 0
    while i < total:
        block = firmware[i:i + 0x100]
        cmd = flash_generateCommand(block, i, total)
        try:
            send_packet(ser, cmd)
            # wait for ack 0x1A (short timeout)
            read_packet(ser, 0x1A, timeout_ms=2000)
        except Exception as e:
            logging.exception("Flash command rejected or timeout")
            raise
        pct = (i / total) * 100
        # replace line: print progress
        logging.info("Flashing... %.1f%%", pct)
        i += 0x100
    logging.info("Flashing... 100.0%%")
    logging.info("Successfully flashed firmware.")


# ---------- CLI & main ----------
def parse_args():
    p = argparse.ArgumentParser(description="Flash Quansheng firmware (Python port of JS flasher logic).")
    p.add_argument("firmware", help="Path to firmware .bin (packed, as downloads)")
    p.add_argument("--port", required=True, help="Serial port (e.g. /dev/ttyUSB0 or COM3)")
    p.add_argument("--baud", type=int, default=38400, help="Serial baudrate (default 38400)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s: %(message)s")

    global rawFirmware, rawVersion

    # Load firmware file
    try:
        with open(args.firmware, "rb") as f:
            encoded = f.read()
    except Exception as e:
        logging.exception("Failed to open firmware file")
        sys.exit(2)

    decoded = unpack(encoded)
    if decoded is None:
        logging.error("Firmware unpack failed. Aborting.")
        sys.exit(1)
    rawFirmware = decoded
    logging.info("Detected firmware version: %s", (rawVersion.split(b'\x00', 1)[0].decode('ascii', errors='ignore') if rawVersion else "<unknown>"))

    cur_size = len(rawFirmware)
    max_size = 0xEFFF
    pct = (cur_size / max_size) * 100
    logging.info("Firmware uses %.2f%% of available memory (%d/%d bytes).", pct, cur_size, max_size)
    if cur_size > max_size:
        logging.error("Firmware is too large and will not work. Aborting.")
        sys.exit(1)

    # Open serial
    try:
        ser = open_serial(args.port, baud=args.baud)
    except Exception as e:
        logging.exception("Failed to open serial port")
        sys.exit(3)

    try:
        # Wait for initial 0x18 packet (radio spam) - try for a few seconds
        try:
            data = read_packet(ser, 0x18, timeout_ms=3000)
        except TimeoutError:
            logging.error("No 0x18 packet received. Make sure the radio is in bootloader/flash mode.")
            sys.exit(4)

        if data[0] == 0x18:
            logging.info("Radio in flash mode detected.")
            # initialize (send version and receive response)
            resp = flash_init(ser)
            if flash_checkVersion(resp, rawVersion):
                logging.info("Version check passed.")
            else:
                logging.warning("Version check failed! Please ensure correct firmware version. Aborting.")
                sys.exit(5)
            logging.info("Flashing firmware...")
            flash_flashFirmware(ser, rawFirmware)
        else:
            logging.error("Received unexpected packet: %s", data.hex())
            sys.exit(6)
    except Exception as e:
        logging.exception("Error during flashing")
        sys.exit(7)
    finally:
        try:
            ser.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

