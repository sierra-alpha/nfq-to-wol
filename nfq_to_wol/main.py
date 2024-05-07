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
        raise ValueError(
            "Incorrect MAC address format - given: {}".format(mac_address)
        )

    send(
        IP(dst="255.255.255.255")
        / UDP(dport=9)
        / Raw(load=bytes.fromhex("F" * 12 + valid_mac_address * 16))
    )


def packet_handler(ping_timeout, hosts, packet):
    daddr = packet[IP].dst if IP in packet else None
    if daddr and daddr in hosts:
        if not sr1(IP(dst=daddr), timeout=ping_timeout):
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
        != ParameterSource.DEFAULT
    ):
        config_data["ping-timeout"] = ping_timeout

    hosts = config_data.get("hosts", {})

    if not hosts:
        raise ValueError(
            "Requires at lest one host to look for, see template config file "
            "for usage requirements."
        )

    callback = partial(packet_handler, config_data["ping-timeout"], hosts)

    sniff(filter="ip dst host {}".format(" or ".join(hosts)), prn=callback)


if __name__ == "__main__":
    main()
