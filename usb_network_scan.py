#!/usr/bin/env python3

import json
import subprocess
from pathlib import Path


SYS_CLASS_NET = Path("/sys/class/net")
SYS_BUS_USB = Path("/sys/bus/usb/devices")


def _read_sysfs(path):
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _usb_device_for_interface(iface_name):
    device_path = (SYS_CLASS_NET / iface_name / "device").resolve()
    for parent in (device_path, *device_path.parents):
        vendor_id = _read_sysfs(parent / "idVendor")
        product_id = _read_sysfs(parent / "idProduct")
        if vendor_id and product_id:
            return {
                "bus": int(_read_sysfs(parent / "busnum") or 0),
                "device": int(_read_sysfs(parent / "devnum") or 0),
                "vendor_id": vendor_id.lower(),
                "product_id": product_id.lower(),
                "manufacturer": _read_sysfs(parent / "manufacturer"),
                "product": _read_sysfs(parent / "product"),
            }
    return None


def get_usb_devices():
    devices = []
    if not SYS_BUS_USB.exists():
        return devices

    for path in sorted(SYS_BUS_USB.iterdir()):
        vendor_id = _read_sysfs(path / "idVendor")
        product_id = _read_sysfs(path / "idProduct")
        bus = _read_sysfs(path / "busnum")
        device = _read_sysfs(path / "devnum")
        if not (vendor_id and product_id and bus and device):
            continue
        devices.append(
            {
                "bus": int(bus),
                "device": int(device),
                "vendor_id": vendor_id.lower(),
                "product_id": product_id.lower(),
                "manufacturer": _read_sysfs(path / "manufacturer"),
                "product": _read_sysfs(path / "product"),
            }
        )
    return devices


def get_usable_network_interfaces():
    result = subprocess.run(
        ["ip", "-j", "addr", "show"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    entries = json.loads(result.stdout)
    interfaces = []

    for entry in entries:
        iface_name = entry.get("ifname")
        if not iface_name:
            continue

        usb_device = _usb_device_for_interface(iface_name)
        addresses = {"ipv4": [], "ipv6": []}
        for address in entry.get("addr_info", []):
            family = address.get("family")
            local = address.get("local")
            if local and family == "inet":
                addresses["ipv4"].append(local)
            elif local and family == "inet6":
                addresses["ipv6"].append(local)

        interface_path = SYS_CLASS_NET / iface_name
        driver_link = interface_path / "device" / "driver"
        try:
            driver = driver_link.resolve(strict=True).name
        except (FileNotFoundError, OSError):
            driver = None

        interfaces.append(
            {
                "name": iface_name,
                "state": entry.get("operstate", "unknown"),
                "mac": entry.get("address"),
                "mtu": entry.get("mtu"),
                "ipv4": addresses["ipv4"],
                "ipv6": addresses["ipv6"],
                "wireless": (interface_path / "wireless").exists()
                or (interface_path / "phy80211").exists(),
                "usb_device": usb_device is not None,
                "usb": usb_device,
                "driver": driver,
            }
        )

    return interfaces


def get_interface_mode(iface_name):
    result = subprocess.run(
        ["iw", "dev", iface_name, "info"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    for line in result.stdout.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0] == "type":
            return parts[1]
    raise ValueError(f"Could not determine the wireless mode for {iface_name}.")


def main():
    print("=" * 70)
    print("  NETSCAN // USB WiFi Interface Detector")
    print("=" * 70)

    usb_devices = get_usb_devices()
    print("\n[1] ALL USB DEVICES:")
    print("-" * 50)
    if not usb_devices:
        print("  No USB devices found.")
    for index, device in enumerate(usb_devices, start=1):
        print(
            f"  {index}. Bus {device['bus']:03d} Device {device['device']:03d}: "
            f"ID {device['vendor_id']}:{device['product_id']}"
        )
        description = " ".join(
            part
            for part in (device["manufacturer"], device["product"])
            if part
        ) or "USB device"
        print(f"     {description}")

    interfaces = [
        iface for iface in get_usable_network_interfaces() if iface["wireless"]
    ]
    print("\n[2] WIRELESS (WLAN) INTERFACES:")
    print("-" * 50)

    if not interfaces:
        print("  No wireless interfaces found.")

    for index, iface in enumerate(interfaces, start=1):
        print("\n  " + "=" * 50)
        print(f"  [{index}] INTERFACE: {iface['name']}")
        print("  " + "=" * 50)
        print(f"  MAC Address:     {iface['mac'] or 'unknown'}")
        print(f"  IP Address:      {', '.join(iface['ipv4']) or 'no IP assigned'}")
        print(f"  IPv6 Address:    {', '.join(iface['ipv6']) or 'none'}")
        print(f"  Driver:          {iface['driver'] or 'unknown'}")
        if iface["usb"]:
            usb = iface["usb"]
            description = " ".join(
                part for part in (usb["manufacturer"], usb["product"]) if part
            ) or "USB device"
            print(
                f"  USB Device:      Bus {usb['bus']:03d} Device "
                f"{usb['device']:03d} ({description})"
            )
        else:
            print("  USB Device:      Not USB-attached")

    print("\n[3] SUMMARY FOR NETSCAN:")
    print("-" * 50)
    print(f"  {len(interfaces)} wireless interface(s) found.")
    for index, iface in enumerate(interfaces, start=1):
        print(f"    {index}. {iface['name']} ({iface['driver'] or 'driver unknown'})")
    print("\n  Read-only inventory; no interface settings were changed.")


if __name__ == "__main__":
    main()
