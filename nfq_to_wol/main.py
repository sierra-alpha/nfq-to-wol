from click.core import ParameterSource
from scapy.all import *
import click
import yaml
from functools import partial


def load_config(file_path):
    with open(file_path, "r") as stream:
        return yaml.safe_load(stream) or {}


# Credit to the GitHub user @remcohaszing for the pywakeonlan package for
# inspiration on this bit of code.
#
def send_wol(mac_address):
    valid_mac_address = (
        mac_address
        if len(mac_address) == 12
        else mac_address.replace(mac_address[4], "")
        if len(mac_address) == 14
        else mac_address.replace(mac_address[2], "")
        if len(mac_address) == 17
        else None
    )

    if not valid_mac_address:
        raise ValueError("Incorrect MAC address format - given: {}".format(mac_address))

    print("Sending WOL, targeting MAC: {}".format(mac_address))
    sendp(
        IP(dst="255.255.255.255")
        / UDP(dport=9)
        / Raw(load=bytes.fromhex("F" * 12 + valid_mac_address * 16))
    )


def packet_handler(ping_timeout, hosts, packet):
    daddr = (
        None
        if Raw in packet and packet[Raw].load == b"Sent from NFQ to WOL"
        else packet[IP].dst if IP in packet
        else packet[ARP].pdst if ARP in packet
        else None
    )
    print("Searching or skipping for {}".format(daddr))
    if daddr and daddr in hosts:
        print("pinging with timeout: {}".format(ping_timeout))
        ping_result = sr1(
            IP(dst=daddr) / ICMP() / Raw(load=b"Sent from NFQ to WOL"),
            timeout=ping_timeout,
        )
        print("ping_results: {}".format(ping_result))
        if ping_result is None or ping_result[IP].src != daddr:
            print("Found sleeping daddr: {}".format(daddr))
            send_wol(hosts[daddr])


@click.command()
@click.option(
    "--config-file",
    type=str,
    default="/etc/nfq-to-wol.yaml",
    help="Path to config file",
)
@click.option(
    "--ping-timeout", type=float, default=1, help="Timeout for ping checks in seconds"
)
def main(config_file, ping_timeout):
    config_data = load_config(config_file)

    if (
        click.get_current_context().get_parameter_source("ping-timeout")
        == ParameterSource.DEFAULT
    ):
        ping_timeout = config_data.get("ping-timeout", ping_timeout)

    hosts = config_data.get("hosts", {})

    if not hosts:
        raise ValueError(
            "Requires at lest one host to look for, see template config file "
            "for usage requirements."
        )

    callback = partial(packet_handler, ping_timeout, hosts)

    sniff_filter = "not icmp and dst net {hosts}".format(
        hosts=" or ".join(hosts)
    )
    print("Using filter: {}".format(sniff_filter))

    sniff(filter=sniff_filter, prn=callback)


if __name__ == "__main__":
    main()
