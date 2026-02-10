# USB Device Handler

The USB Device Handler is a KubeArmor module that provides audit and enforcement capabilities for USB devices at the host level.
It allows administrators to define fine-grained host security policies that control USB device access based on their class, subclass, protocol, and level.

To enable USB device enforcement, use the `enableUSBDeviceHandler` flag.

Note that the USB Device Handler requires host policies to be enabled as well.
It operates only with KubeArmor host policies.

You can define policies that enforce actions on specific USB devices by their hardware classification.
See the policy spec [here](host_security_policy_specification.md).

## Working

The USB Device Handler works by:

1. Listening to kernel uevents via a Netlink socket for USB device attachments and removals.
2. When a USB device is attached, it matches the device against the currently applied host policies.
3. The most specific matching policy is selected and its action (Allow, Audit, or Block) is enforced.
4. Enforcement is achieved through [sysfs-based USB authorization](https://docs.kernel.org/usb/authorization.html), by modifying the device configuration under `/sys/bus/usb/devices/`.

## Logs

When the handler reports a USB event, the generated log includes time fields:

- `Timestamp`: numeric timestamp populated by KubeArmor.
- `UpdatedTime`: RFC 3339 / ISO 8601 timestamp string populated by KubeArmor.

Example (fields shown are a subset of a full log):

Example (fields shown are a subset of a full log):

```json
{
  "Timestamp": 1770693725,
  "UpdatedTime": "2026-02-10T03:22:05.471945Z",
  "Operation": "Device",
  "Resource": "USB MASS-STORAGE",
  "Data": "Class=8 SubClass=6 Protocol=80 Level=2 SysPath=/sys/bus/usb/devices/2-4.1:1.0",
  "EventData": {
    "Class": "8",
    "Level": "2",
    "Protocol": "80",
    "SubClass": "6",
    "SysPath": "/sys/bus/usb/devices/2-4.1:1.0"
  },
  "Result": "Passed"
}
```

## Policy Handling

The handler maintains an ordered list of rules, sorted by their specificity.
Specificity is determined by the number of defined fields among:
* class
* subclass
* protocol
* level

#### Specificity Rules
* Each defined property increases the rule’s specificity.
* Rules are sorted in decreasing order of specificity.
* If multiple rules have the same specificity, action priority decides which one is used: Block > Audit > Allow

For example, consider these three host policies:

| # | Class | Sub Class | Protocol | Level | Action |
|---|-------|-----------|----------|-------|--------|
|1  |8      |6          |80        |2      |Allow   |
|2  |8      |6          |80        |2      |Block   |
|3  |8      |6          |-         |2      |Audit   |

After evaluation, the handler will generate the following internal rules:

| # | Class (100) | Sub Class (10) | Protocol (1) | Level (100) | Action | Specificity |
|---|-------|-----------|----------|-------|--------|-------------|
|1  |8      |6          |80        |2      |Block   |211          |
|2  |8      |6          |-         |2      |Audit   |210          |

Note that the Allow rule (policy #1) was replaced by the Block rule (policy #2) because they target the same device attributes and Block has higher priority.

## Enforcement Mode

If there is at least one Allow rule, the handler operates in Allowlist Mode. Devices not matching any policy will have their behavior decided by the host default device posture. It can be `audit` or `block` (default is `audit`).

You can configure this using the `hostDefaultDevicePosture` flag.


## Supported USB Classes

| Decimal | Hex  | Class Name              | Description |
|---------|------|-------------------------|-------------|
| 1       | 0x01  | AUDIO                  | Audio devices |
| 2       | 0x02  | COMMUNICATION-CDC      | Communications & CDC Control |
| 3       | 0x03  | HID                    | Human Interface Devices (keyboard, mouse etc.) |
| 5       | 0x05  | PHYSICAL               | Physical devices |
| 6       | 0x06  | IMAGE                  | Cameras, scanners |
| 7       | 0x07  | PRINTER                | Printers |
| 8       | 0x08  | MASS-STORAGE           | Storage devices (flash drives, external HDDs, etc.) |
| 9       | 0x09  | HUB                    | Hubs |
| 10      | 0x0A  | CDC-DATA               | CDC Data interface |
| 11      | 0x0B  | SMART-CARD             | Smart Card readers |
| 13      | 0x0D  | CONTENT-SECURITY       | Content security devices |
| 14      | 0x0E  | VIDEO                  | Video devices (Webcams, capture cards) |
| 15      | 0x0F  | PERSONAL-HEALTHCARE    | Healthcare/medical devices |
| 16      | 0x10  | AUDIO/VIDEO            | Audio/Video devices |
| 17      | 0x11  | BILLBOARD              | Billboard devices |
| 18      | 0x12  | TYPE-C-BRIDGE          | Type-C bridge devices |
| 19      | 0x13  | BULK-DISPLAY           | Bulk Display Protocol devices |
| 20      | 0x14  | MCTP                   | MCTP over USB protocol endpoint |
| 60      | 0x3C  | I3C                    | I3C over USB devices |
| 220     | 0xDC  | DIAGNOSTIC             | Diagnostic devices |
| 224     | 0xE0  | WIRELESS-CONTROLLER    | Wireless controllers (Bluetooth, WiFi adapters) |
| 239     | 0xEF  | MISCELLANEOUS          | Miscellaneous devices |
| 254     | 0xFE  | APPLICATION-SPECIFIC   | Application-defined class |
| 255     | 0xFF  | VENDOR-SPECIFIC        | Vendor-defined proprietary class |

As defined by [usb.org](https://www.usb.org/defined-class-codes).

## Policy examples

* Keyboard

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorHostPolicy
    metadata:
      name: hsp-block-keybd
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: aryan
      severity: 5
      device:
        matchDevice:
        - class: HID
          subClass: 1
          protocol: 1
      action: Block
    ```
    The above policy will block USB keyboards attached at any level to the host with hostname `aryan`

* Mouse

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorHostPolicy
    metadata:
    name: hsp-audit-mouse
    spec:
    nodeSelector:
        matchLabels:
        kubernetes.io/hostname: aryan
    severity: 5
    device:
        matchDevice:
        - class: "0x3"
        subClass: 1
        protocol: 2
        level: 1
    action: Audit
    ```
    The above policy will audit USB mice attached directly to the host with hostname `aryan`

<br>

### Known Limitation: Composite USB Devices (Mouse + Keyboard)
When a composite USB device that controls both mouse and keyboard is connected, and a KubeArmor policy is applied to block either one of them (for example, the mouse or the keyboard interface), both stop functioning.
In `sysfs`  although, only the targeted interface is deauthorized according to the policy. But the entire composite device becomes unavailable to the system.
