from click.core import ParameterSource
from functools import partial
from scapy.all import *
import click
import logging
import yaml

logger = logging.getLogger(__name__)


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

    logger.info("Sending WOL, targeting MAC: {}".format(mac_address))
    sendp(
        IP(dst="255.255.255.255")
        / UDP(dport=9)
        / Raw(load=bytes.fromhex("F" * 12 + valid_mac_address * 16))
    )


def packet_handler(ping_timeout, hosts, packet):
    we_sent_it_id = b"Sent from NFQ to WOL"
    daddr = (
        None
        if Raw in packet and packet[Raw].load == we_sent_it_id
        else packet[IP].dst
        if IP in packet
        else packet[ARP].pdst
        if ARP in packet
        else None
    )
    logger.debug("Searching or skipping for {}".format(daddr))
    if daddr and daddr in hosts:
        logger.debug("pinging with timeout: {}".format(ping_timeout))
        ping_result = sr1(
            IP(dst=daddr) / ICMP() / Raw(load=we_sent_it_id),
            timeout=ping_timeout,
        )
        logger.debug("ping_results: {}".format(ping_result))
        if ping_result is None or ping_result[IP].src != daddr:
            logger.debug("Found sleeping daddr: {}".format(daddr))
            logger.info("Sending WOL, because of packet: {}".format(packet))
            send_wol(hosts[daddr])


def validate_log_level(ctx, param, value):
    debug_levels = "DEBUG INFO WARNING ERROR CRITICAL".split()
    if value.upper() in debug_levels:
        return value.upper()

    raise click.BadParameter(
        "format must be one of {}.".format(", ".join(debug_levels))
    )


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
@click.option(
    "--log-level",
    type=str,
    callback=validate_log_level,
    default="WARNING",
    help="Log level for output",
)
def main(config_file, ping_timeout, log_level):
    logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)
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

    sniff_filter = "dst net {hosts}".format(hosts=" or ".join(hosts))
    logger.info("Using filter: {}".format(sniff_filter))

    sniff(filter=sniff_filter, prn=callback)


if __name__ == "__main__":
    main()
