# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

"""Verify quota accounting and packet verdicts in a disposable network namespace."""

import json
import socket
import struct
import subprocess
import sys
import time


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)


def quota(name):
    objects = json.loads(run("nft", "-j", "list", "quota", "inet", "kubearmor", name))
    return next(obj["quota"] for obj in objects["nftables"] if "quota" in obj)


def passed():
    objects = json.loads(run("nft", "-j", "list", "counter", "inet", "ka_verify", "passed"))
    return next(obj["counter"]["packets"] for obj in objects["nftables"] if "counter" in obj)


def container_sender():
    run("ip", "link", "add", "ka-in", "type", "veth", "peer", "name", "ka-send")
    run("ip", "addr", "add", "172.18.0.1/24", "dev", "ka-in")
    for interface in ("ka-in", "ka-send"):
        run("ip", "link", "set", interface, "up")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as forwarding:
        forwarding.write("1")
    address = json.loads(run("ip", "-j", "link", "show", "ka-in"))[0]["address"]
    mac = bytes.fromhex(address.replace(":", ""))

    # Inject an Ethernet/IPv4/UDP packet through the veth peer into FORWARD.
    header = struct.pack(
        "!BBHHHBBH4s4s", 69, 0, 1028, 1, 0, 64, 17, 0,
        socket.inet_aton("172.18.0.2"), socket.inet_aton("198.18.0.2"),
    )
    checksum = sum(struct.unpack("!10H", header))
    checksum = (checksum & 65535) + (checksum >> 16)
    checksum = (checksum & 65535) + (checksum >> 16)
    header = header[:10] + struct.pack("!H", (~checksum) & 65535) + header[12:]
    packet = (
        mac + bytes.fromhex("020000000003") + b"\x08\x00" + header
        + struct.pack("!HHHH", 50000, 9000, 1008, 0) + b"x" * 1000
    )
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sender.bind(("ka-send", 0))
    return sender, packet


def main():
    target, quota_name = sys.argv[1:]
    run("ip", "link", "add", "ka-out", "type", "dummy")
    run("ip", "addr", "add", "198.18.0.1/24", "dev", "ka-out")
    run("ip", "link", "set", "ka-out", "up")
    run(
        "ip", "neigh", "replace", "198.18.0.2", "lladdr", "02:00:00:00:00:02",
        "nud", "permanent", "dev", "ka-out",
    )
    run("nft", "add", "table", "inet", "ka_verify")
    run("nft", "add", "counter", "inet", "ka_verify", "passed")
    run(
        "nft", "add", "chain", "inet", "ka_verify", "post",
        "{ type filter hook postrouting priority 300; policy accept; }",
    )
    run(
        "nft", "add", "rule", "inet", "ka_verify", "post",
        "oifname", "ka-out", "counter", "name", "passed",
    )
    if target == "host":
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.connect(("198.18.0.2", 9000))
        packet = b"x" * 1000
    else:
        sender, packet = container_sender()

    try:
        for _ in range(6000):
            sender.send(packet)
        time.sleep(0.2)
        current_quota = quota(quota_name)
        before = passed()
        assert current_quota["used"] >= current_quota["bytes"], current_quota
        assert before > 0, "no packets passed before quota exhaustion"
        for _ in range(50):
            sender.send(packet)
        time.sleep(0.2)
        after = passed()
        if target == "host":
            assert after > before, ("Audit blocked traffic", before, after)
        else:
            assert after == before, ("Block allowed traffic over quota", before, after)
        print(json.dumps({
            "target": target, "quota": current_quota,
            "passed_before": before, "passed_after_over_quota": after,
        }))

        run("nft", "reset", "quota", "inet", "kubearmor", quota_name)
        for _ in range(50):
            sender.send(packet)
        time.sleep(0.2)
        reset = passed()
        assert reset > after, ("traffic did not resume after reset", after, reset)
        print(json.dumps({"reset_passed_packets": reset, "quota_after_reset": quota(quota_name)}))
    finally:
        sender.close()
        run("nft", "delete", "table", "inet", "ka_verify")
        run("ip", "link", "del", "ka-out")
        if target != "host":
            run("ip", "link", "del", "ka-in")


if __name__ == "__main__":
    main()
