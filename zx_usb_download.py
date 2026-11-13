#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zx_usb_download.py - ZX297520V3 USB Download Protocol (Two-Stage RAM Boot)

Reimplemented from zx297520v3-loader-main (Rust/nusb) reference.
Uses raw USB bulk endpoints (pyusb) for reliable Stage 1 → Stage 2 handoff.
Falls back to pyserial CDC if libusb driver is not installed.

Protocol:
  BootROM  ←→  PC:  0x5A/0xA5 handshake → download tloader to SRAM → jump
  Openloader ←→ PC: 0x5A/0xA5 handshake → download u-boot to DDR  → jump → boot_ap()
"""
import sys
import os
import struct
import time
import argparse

# ---------------------------------------------------------------------------
# Protocol constants (identical in BootROM, openloader, and reference tool)
# ---------------------------------------------------------------------------
SYNC_FLAG           = 0x5A
WRITE32_FLAG        = 0x6A
DOWNLOAD_FLAG       = 0x7A
RUN_FLAG            = 0x8A

SYNC_ACK            = 0xA5
WRITE32_ACK         = 0xA6
DOWNLOAD_HEADER_ACK = 0xA1
DOWNLOAD_DONE_ACK   = 0xA7
RUN_ACK             = 0xA8

# Stage 2 stock tboot sync (different ACK byte)
STAGE2_SYNC         = 0x5A
STAGE2_SYNC_ACK     = 0xA7

# Addresses from zx297520v3-loader-main/src/lib.rs & main.rs
STAGE1_BASE         = 0x00082000   # SRAM - openloader/tloader
STAGE2_BASE_STOCK   = 0x27EF0000  # DDR  - stock tboot
STAGE2_BASE_MAINLINE= 0x21DF0000  # DDR  - mainline u-boot (CONFIG_TEXT_BASE)

# Chunk sizes matching reference
STAGE1_CHUNK        = 0x2000       # 8 KB
STAGE2_CHUNK        = 0x20000      # 128 KB

# ZTE USB IDs
ZTE_VID             = 0x19D2
ZTE_PID             = 0x0256

# Header constants
HEADER_SIZE         = 0x1B8        # 440 bytes
HEADER_MAGIC        = b'ZX7521V1'

# Secure boot exploit address (CVE-2026-40003)
EXPLOIT_ADDR        = 0x81FD0

# ---------------------------------------------------------------------------
# 0x1B8 Header builder (for raw openloader binaries that lack the header)
# ---------------------------------------------------------------------------
def build_default_header(payload_size, entry_addr):
    """Build a minimal 0x1B8 byte header matching header.rs defaults."""
    hdr = bytearray(HEADER_SIZE)
    hdr[0] = 0x08          # unk
    hdr[1] = 0x00          # unk1
    hdr[2] = 0x5A          # usbdl flag
    hdr[3] = 0x00          # timeout_multiplier
    hdr[4:12] = HEADER_MAGIC
    struct.pack_into('<I', hdr, 12, payload_size)   # data_size (LE)
    # rsa_pub_e[128] @ 16  -> zeros
    # rsa_pub_n[128] @ 144 -> zeros
    # reserved[112]  @ 272 -> zeros
    # hash[16]       @ 384 -> zeros
    # unk2(u16)      @ 400 -> 0
    # unk3(u16)      @ 402 -> 0
    struct.pack_into('<I', hdr, 404, 0x8A000)       # stack
    struct.pack_into('<I', hdr, 408, entry_addr)     # entry
    # panic(u32)     @ 412 -> 0
    # panic1(u32)    @ 416 -> 0
    # bss_start(u32) @ 420 -> 0
    struct.pack_into('<H', hdr, 424, 0xC046)         # nop[0] (thumb NOP)
    struct.pack_into('<H', hdr, 426, 0xC046)         # nop[1]
    # bss_end(u32)   @ 428 -> 0
    struct.pack_into('<I', hdr, 432, 0x82000000)     # para_start
    struct.pack_into('<I', hdr, 436, 0x82000050)     # para_end
    return bytes(hdr)


def check_header(payload):
    """Check if payload starts with a valid 0x1B8 header. Returns (has_header, entry_addr)."""
    if len(payload) < HEADER_SIZE:
        return False, STAGE1_BASE
    magic = payload[4:12]
    if magic == HEADER_MAGIC:
        entry = struct.unpack_from('<I', payload, 408)[0]
        return True, entry
    return False, STAGE1_BASE


# ===================================================================
#  Transport abstraction: USB Bulk (primary) / Serial CDC (fallback)
# ===================================================================

class UsbBulkTransport:
    """Raw USB bulk endpoint transport via pyusb (matches nusb reference)."""

    def __init__(self, dev, interface=0, ep_in=0x81, ep_out=0x01):
        self.dev = dev
        self.ep_in = ep_in
        self.ep_out = ep_out
        self.intf = interface
        # Claim interface
        try:
            if dev.is_kernel_driver_active(interface):
                dev.detach_kernel_driver(interface)
        except (NotImplementedError, Exception):
            pass
        dev.set_configuration()
        import usb.util
        usb.util.claim_interface(dev, interface)
        print(f"[+] USB bulk transport ready (EP IN 0x{ep_in:02X}, EP OUT 0x{ep_out:02X})")

    def write(self, data):
        self.dev.write(self.ep_out, data, timeout=5000)

    def read(self, size=1, timeout=5000):
        return bytes(self.dev.read(self.ep_in, size, timeout=timeout))

    def read_byte(self, timeout=5000):
        data = self.read(1, timeout)
        if not data:
            raise IOError("USB read timeout")
        return data[0]

    def close(self):
        try:
            import usb.util
            usb.util.release_interface(self.dev, self.intf)
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass

    @property
    def name(self):
        return f"USB({ZTE_VID:04X}:{ZTE_PID:04X})"


class SerialTransport:
    """pyserial CDC fallback transport."""

    def __init__(self, ser):
        self.ser = ser

    def write(self, data):
        self.ser.write(data)
        self.ser.flush()

    def read(self, size=1, timeout=5000):
        old = self.ser.timeout
        self.ser.timeout = timeout / 1000.0
        data = self.ser.read(size)
        self.ser.timeout = old
        return data

    def read_byte(self, timeout=5000):
        data = self.read(1, timeout)
        if not data:
            raise IOError("Serial read timeout")
        return data[0]

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    @property
    def name(self):
        return self.ser.port


# ---------------------------------------------------------------------------
#  Protocol operations (transport-agnostic)
# ---------------------------------------------------------------------------

def do_sync(tp, timeout=5000):
    """Send 0x5A, expect 0xA5."""
    tp.write(bytes([SYNC_FLAG]))
    ack = tp.read_byte(timeout)
    if ack != SYNC_ACK:
        raise IOError(f"Sync failed: expected 0xA5, got 0x{ack:02X}")
    return True


def do_download(tp, payload, load_addr, chunk_size=STAGE1_CHUNK):
    """Download payload to target address."""
    if isinstance(tp, SerialTransport):
        chunk_size = min(chunk_size, 8192)
    size = len(payload)
    print(f"[*] Downloading {size:,} bytes → 0x{load_addr:08X} (chunk={chunk_size:#x}) ...")

    # Send header: [0x7A] [addr:4 BE] [size:4 BE]
    hdr = bytes([DOWNLOAD_FLAG]) + struct.pack('>II', load_addr, size)
    tp.write(hdr)

    ack = tp.read_byte(timeout=5000)
    if ack != DOWNLOAD_HEADER_ACK:
        raise IOError(f"Download header rejected: 0x{ack:02X}")

    # Stream payload
    sent = 0
    t0 = time.time()
    while sent < size:
        chunk = payload[sent:sent + chunk_size]
        tp.write(chunk)
        sent += len(chunk)
        elapsed = max(0.001, time.time() - t0)
        speed = (sent / 1024.0) / elapsed
        sys.stdout.write(f"\r    {sent:,}/{size:,} ({sent*100//size}%) @ {speed:.0f} KB/s")
        sys.stdout.flush()
    print()

    ack = tp.read_byte(timeout=10000)
    if ack != DOWNLOAD_DONE_ACK:
        raise IOError(f"Download completion failed: 0x{ack:02X}")
    print("[+] Download verified (0xA7)")
    return True


def do_jump(tp, addr):
    """Send RUN command to execute at addr."""
    print(f"[*] Jump → 0x{addr:08X}")
    cmd = bytes([RUN_FLAG]) + struct.pack('>I', addr)
    tp.write(cmd)
    ack = tp.read_byte(timeout=5000)
    if ack != RUN_ACK:
        print(f"[?] Jump ACK: 0x{ack:02X} (expected 0xA8)")
    else:
        print("[+] Jump accepted (0xA8)")
    return True


def do_joselito(tp, entry_addr):
    """
    CVE-2026-40003 secure boot bypass.
    Writes entry address ×8 to SRAM 0x81FD0, causing BootROM's
    pop {{r4, pc}} to jump to our controlled address.
    """
    print(f"[*] Joselito exploit: disabling secure boot ...")
    print(f"    Target SRAM: 0x{EXPLOIT_ADDR:08X}, redirect → 0x{entry_addr:08X}")
    payload = struct.pack('<I', entry_addr) * 8   # 32 bytes
    do_download(tp, payload, EXPLOIT_ADDR, chunk_size=STAGE1_CHUNK)
    print("[+] Secure boot bypassed!")


def do_write32(tp, addr, value):
    """Write a 32-bit value to a memory address."""
    cmd = bytes([WRITE32_FLAG]) + struct.pack('>II', addr, value)
    tp.write(cmd)
    # Only gets ACK if addr==0 (protocol quirk); otherwise fire-and-forget
    if addr == 0:
        ack = tp.read_byte(timeout=2000)
        if ack != WRITE32_ACK:
            raise IOError(f"Write32 ACK failed: 0x{ack:02X}")


# ---------------------------------------------------------------------------
#  USB device discovery & connection
# ---------------------------------------------------------------------------

def find_usb_device():
    """Find ZTE USB download device via pyusb."""
    try:
        import usb.core
        dev = usb.core.find(idVendor=ZTE_VID, idProduct=ZTE_PID)
        return dev
    except Exception:
        return None


def find_serial_port(hint=None):
    """Find ZTE DL1 serial port via pyserial, strictly excluding debug UARTs and DL2."""
    try:
        import serial
        import serial.tools.list_ports
        ports = serial.tools.list_ports.comports()
        if hint:
            for p in ports:
                if hint.lower() in p.device.lower():
                    return p.device

        # Pass 1: Look specifically for "dl1" or "mi_00" (ZTE Download Port 1)
        for p in ports:
            hwid = (p.hwid or "").lower()
            desc = (p.description or "").lower()
            # Ignore debug UARTs
            if any(dbg in desc or dbg in hwid for dbg in ["ch34", "1a86", "cp210", "ftdi"]):
                continue
            if "dl1" in desc or ("19d2" in hwid and "0256" in hwid and "mi_00" in hwid):
                print(f"\n[+] Auto-detected ZTE DL1 port: {p.device} ({p.description})")
                return p.device

        # Pass 2: Look for ZTE 19D2:0256 port, strictly ignoring DL2 / mi_01
        for p in ports:
            hwid = (p.hwid or "").lower()
            desc = (p.description or "").lower()
            if any(dbg in desc or dbg in hwid for dbg in ["ch34", "1a86", "cp210", "ftdi"]):
                continue
            if "dl2" in desc or "mi_01" in hwid:
                continue  # Never pick DL2
            if "19d2" in hwid and "0256" in hwid:
                print(f"\n[+] Auto-detected ZTE download port: {p.device} ({p.description})")
                return p.device
    except ImportError:
        pass
    return None


def wait_for_device(max_wait=120.0, prefer_usb=True, port_hint=None):
    """
    Wait for ZTE device to appear.
    Returns (transport, mode) where mode is 'usb' or 'serial'.
    """
    mode_str = "Serial CDC" if not prefer_usb else "USB bulk"
    if port_hint:
        mode_str += f" ({port_hint})"
    print(f"[*] Waiting for ZTE download interface ...")
    print(f"    Mode: {mode_str}")
    spinner = ["|", "/", "-", "\\"]
    t0 = time.time()
    idx = 0

    while time.time() - t0 < max_wait:
        # If not forcing serial, try USB bulk first
        if prefer_usb and not port_hint:
            dev = find_usb_device()
            if dev is not None:
                try:
                    tp = UsbBulkTransport(dev)
                    return tp, 'usb'
                except Exception as e:
                    print(f"\n[!] USB bulk open failed ({e}), falling back to serial ...")
                    prefer_usb = False

        # Try serial
        port = find_serial_port(port_hint)
        if port:
            try:
                import serial
                ser = serial.Serial(port, 115200, timeout=0.05, write_timeout=1.0)
                try:
                    ser.set_buffer_size(rx_size=262144, tx_size=262144)
                except Exception:
                    pass
                print(f"\n[+] Serial port opened: {port}")
                tp = SerialTransport(ser)
                return tp, 'serial'
            except Exception as e:
                # May fail if port is momentarily busy while enumerating
                pass

        if idx % 4 == 0:
            elapsed = time.time() - t0
            sys.stdout.write(f"\r[*] Scanning [{spinner[idx % 4]}] {elapsed:.0f}s ...")
            sys.stdout.flush()
        idx += 1
        time.sleep(0.5)

    print(f"\n[-] Device not found after {max_wait:.0f}s")
    return None, None


def wait_for_handshake(tp, max_wait=30.0, banner="Handshake"):
    """Poll 0x5A → 0xA5 handshake on existing transport."""
    print(f"[*] {banner}: polling sync on {tp.name} ...")
    t0 = time.time()
    while time.time() - t0 < max_wait:
        try:
            tp.write(bytes([SYNC_FLAG]))
            ack = tp.read(1, timeout=50)
            if ack and ack[0] in (SYNC_ACK, DOWNLOAD_DONE_ACK):
                elapsed = time.time() - t0
                print(f"[+] {banner} locked in {elapsed:.2f}s (0x{ack[0]:02X})")
                return True
        except Exception:
            pass
        time.sleep(0.015)

    elapsed = time.time() - t0
    sys.stdout.write(f"\r[*] {banner}: {elapsed:.1f}s ...")
    sys.stdout.flush()

    print(f"\n[-] {banner} timed out after {max_wait:.0f}s")
    return False


# ---------------------------------------------------------------------------
#  Main two-stage boot flow
# ---------------------------------------------------------------------------

def two_stage_boot(args):
    stage1_path = args.stage1
    stage2_path = args.stage2
    sram_addr   = args.sram
    ddr_addr    = args.ddr
    exploit     = args.exploit
    stock       = args.stock
    use_serial  = args.serial

    print("=" * 68)
    print("   ZX297520V3 USB Download Protocol — Two-Stage RAM Boot")
    print("=" * 68)
    print(f" Stage 1: {stage1_path} → SRAM 0x{sram_addr:08X}")
    print(f" Stage 2: {stage2_path} → DDR  0x{ddr_addr:08X}")
    if exploit:
        print(" [!] Secure boot exploit (Joselito) ENABLED")
    if stock:
        print(" [*] Stock tboot sync mode")
    print("=" * 68)

    # Validate files
    if not os.path.isfile(stage1_path):
        print(f"[-] Stage 1 not found: {stage1_path}")
        return False
    if not os.path.isfile(stage2_path):
        print(f"[-] Stage 2 not found: {stage2_path}")
        return False

    stage1_data = open(stage1_path, "rb").read()
    stage2_data = open(stage2_path, "rb").read()
    print(f"[*] Stage 1: {len(stage1_data):,} bytes")
    print(f"[*] Stage 2: {len(stage2_data):,} bytes")

    # --- Check / prepend header on stage1 ---
    has_hdr, hdr_entry = check_header(stage1_data)
    if has_hdr:
        print(f"[*] Stage 1 has 0x1B8 header (magic=ZX7521V1, entry=0x{hdr_entry:08X})")
        entry_for_exploit = hdr_entry
    else:
        print("[*] Stage 1 has NO header — prepending default 0x1B8 header")
        entry_addr = (sram_addr + HEADER_SIZE) | 1   # Thumb bit
        hdr_bytes = build_default_header(len(stage1_data), entry_addr)
        stage1_data = hdr_bytes + stage1_data
        entry_for_exploit = entry_addr
        print(f"    New total: {len(stage1_data):,} bytes, entry=0x{entry_addr:08X}")

    # --- Connect to device ---
    print()
    tp, mode = wait_for_device(max_wait=120.0, prefer_usb=not use_serial, port_hint=getattr(args, 'port', None))
    if tp is None:
        print("[-] Could not connect to device. Ensure USB cable and device power.")
        return False

    try:
        # === PHASE 1: BootROM ===
        print(f"\n{'='*50}")
        print(f" PHASE 1 — BootROM ({mode.upper()} mode)")
        print(f"{'='*50}")

        # Initial handshake
        if not wait_for_handshake(tp, max_wait=60.0, banner="BootROM Sync"):
            tp.close()
            return False

        # Exploit if requested
        if exploit:
            do_joselito(tp, entry_for_exploit)

        # Upload stage 1
        print()
        do_download(tp, stage1_data, sram_addr, chunk_size=STAGE1_CHUNK)

        # Jump to stage 1
        do_jump(tp, sram_addr)
        print("[+] Stage 1 launched! Openloader initializing DRAM ...")

        # === PHASE 2: Openloader ===
        # Key insight from reference: openloader does NOT re-enumerate USB.
        # It reuses BootROM's existing USB setup. Same endpoints, same handle.
        # Just need to wait for it to initialize and start its protocol loop.

        print(f"\n{'='*50}")
        print(f" PHASE 2 — Openloader ({mode.upper()} mode)")
        print(f"{'='*50}")

        # Small delay for DRAM init
        time.sleep(0.5)

        # Handshake with openloader (same transport, no reconnect needed!)
        if not wait_for_handshake(tp, max_wait=30.0, banner="Openloader Sync"):
            print("[!] Openloader sync failed. Check UART output for errors.")
            print("[!] Common causes: wrong STAGE1_BASE, DRAM init failure, secure boot block")
            tp.close()
            return False

        # Upload stage 2
        print()
        do_download(tp, stage2_data, ddr_addr, chunk_size=STAGE2_CHUNK)

        # Jump to stage 2
        do_jump(tp, ddr_addr)

        # Stock tboot needs an extra sync
        if stock:
            print("[*] Waiting for stock tboot sync ...")
            tp.write(bytes([STAGE2_SYNC]))
            ack = tp.read_byte(timeout=5000)
            if ack == STAGE2_SYNC_ACK:
                print("[+] Stock tboot sync OK")
            else:
                print(f"[?] Stock tboot sync: 0x{ack:02X}")

        # === SUCCESS ===
        print()
        print("=" * 68)
        print(" ✓ SUCCESS — U-Boot loaded to DDR and Cortex-A7 is running!")
        print()
        print("   Boot output: UART ")
        print("   Web Failsafe: http://192.168.72.1")
        print("=" * 68)

        tp.close()
        return True

    except IOError as e:
        print(f"\n[-] Protocol error: {e}")
        tp.close()
        return False
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        tp.close()
        return False


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ZX297520V3 USB Download Tool (pyusb bulk / pyserial CDC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Serial mode (no WinUSB needed, preserves RNDIS driver!)
  python zx_usb_download.py -e --serial

  # Specify COM port directly
  python zx_usb_download.py -e --serial -p COM97

  # Auto-detect USB bulk mode
  python zx_usb_download.py -e
""")
    parser.add_argument("-p", "--port", default=None,
                        help="Target serial port (e.g. COM97). Auto-detects DL1 if omitted.")
    parser.add_argument("-1", "--stage1", default="./tloader.bin",
                        help="Stage 1 binary (tloader/openloader) [default: ./tloader.bin]")
    parser.add_argument("-2", "--stage2", default="./u-boot.bin",
                        help="Stage 2 binary (u-boot/tboot) [default: ./u-boot.bin]")
    parser.add_argument("--sram", type=lambda x: int(x, 0), default=STAGE1_BASE,
                        help=f"Stage 1 SRAM load address [default: 0x{STAGE1_BASE:08X}]")
    parser.add_argument("--ddr", type=lambda x: int(x, 0), default=STAGE2_BASE_MAINLINE,
                        help=f"Stage 2 DDR load address [default: 0x{STAGE2_BASE_MAINLINE:08X}]")
    parser.add_argument("-e", "--exploit", action="store_true",
                        help="Enable Joselito secure boot bypass (CVE-2026-40003)")
    parser.add_argument("-s", "--stock", action="store_true",
                        help="Stock tboot sync mode (extra 0x5A/0xA7 handshake after stage2 jump)")
    parser.add_argument("--serial", action="store_true",
                        help="Force serial CDC mode (skip USB bulk attempt)")
    args = parser.parse_args()

    if not two_stage_boot(args):
        sys.exit(1)


if __name__ == "__main__":
    main()
