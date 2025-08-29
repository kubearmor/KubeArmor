# Supported USB Device Classes & Subclasses

This document lists the USB device classes and subclasses supported for device spec in KubeArmor Host Policy as defined in [USB Defined Class Codes](https://www.usb.org/defined-class-codes).

## Supported USB Classes

| Decimal | Hex  | Class Name             | Description |
|---------|------|------------------------|-------|
| 1       | 01h  | AUDIO                  | Audio devices |
| 2       | 02h  | COMMUNICATION-CDC      | Communications & CDC Control |
| 3       | 03h  | HID                    | Human Interface Devices (see subclasses below) |
| 5       | 05h  | PHYSICAL               | Physical devices |
| 6       | 06h  | IMAGE                  | Cameras, scanners |
| 7       | 07h  | PRINTER                | Printers |
| 8       | 08h  | MASS-STORAGE           | Storage devices (flash drives, external HDDs, etc.) |
| 9       | 09h  | HUB                    | Hubs |
| 10      | 0Ah  | CDC-DATA               | CDC Data interface |
| 11      | 0Bh  | SMART-CARD             | Smart Card readers |
| 13      | 0Dh  | CONTENT-SECURITY       | Content security devices |
| 14      | 0Eh  | VIDEO                  | Video devices (Webcams, capture cards) |
| 15      | 0Fh  | PERSONAL-HEALTHCARE    | Healthcare/medical devices |
| 16      | 10h  | AUDIO/VIDEO            | Audio/Video devices |
| 17      | 11h  | BILLBOARD              | Billboard devices |
| 18      | 12h  | TYPE-C-BRIDGE          | Type-C bridge devices |
| 19      | 13h  | BULK-DISPLAY           | Bulk Display Protocol devices |
| 20      | 14h  | MCTP                   | MCTP over USB protocol endpoint |
| 60      | 3Ch  | I3C                    | I3C over USB devices |
| 220     | DCh  | DIAGNOSTIC             | Diagnostic devices |
| 224     | E0h  | WIRELESS-CONTROLLER    | Wireless controllers (Bluetooth, WiFi adapters) |
| 239     | EFh  | MISCELLANEOUS          | Miscellaneous devices |
| 254     | FEh  | APPLICATION-SPECIFIC   | Application-defined class |
| 255     | FFh  | VENDOR-SPECIFIC        | Vendor-defined proprietary class |

---

## Supported USB Subclasses

Currently, **only HID (Human Interface Device)** class supports subclasses in policy specification:

| Class | Subclass   | Description   |
|-------|------------|---------------|
| HID   | KEYBOARD   | USB Keyboards |
| HID   | MOUSE      | USB Mice      |
