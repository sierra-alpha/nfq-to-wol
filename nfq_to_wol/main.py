from click.core import ParameterSource
from functools import partial
from scapy.all import *
import click
import logging
import yaml
from multiprocessing import SimpleQueue, Process
from concurrent.futures import ProcessPoolExecutor

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
        else (
            mac_address.replace(mac_address[4], "")
            if len(mac_address) == 14
            else (
                mac_address.replace(mac_address[2], "")
                if len(mac_address) == 17
                else None
            )
        )
    )

    if not valid_mac_address:
        raise ValueError("Incorrect MAC address format - given: {}".format(mac_address))

    logger.info("Sending WOL, targeting MAC: {}".format(mac_address))
    send(
        Ether()
        / IP(dst="255.255.255.255")
        / UDP(dport=9)
        / Raw(load=bytes.fromhex("F" * 12 + valid_mac_address * 16))
    )


def we_sent_it(packet, we_sent_it_id):
    load = Raw in packet and packet[Raw].load
    result = load == we_sent_it_id
    logger.debug("In we_sent_it, Raw load is {}, we_sent_it? {}".format(load, result))
    return result


def packet_handler(ping_timeout, hosts, packet, we_sent_it_id):
    logger.debug("In packet_handler, got packet: {}".format(packet))
    daddr = (
        packet[IP].dst if IP in packet else packet[ARP].pdst if ARP in packet else None
    )
    logger.debug(
        "Searching in configured hosts - daddr: {}, packet {}".format(daddr, packet)
    )
    if not we_sent_it(packet, we_sent_it_id) and hosts.get(daddr):
        logger.debug("Found host - daddr: {}".format(daddr))
        logger.debug("pinging with timeout: {}".format(ping_timeout))
        ping_result = sr1(
            IP(dst=daddr) / ICMP() / Raw(load=we_sent_it_id),
            timeout=ping_timeout,
        )
        logger.debug("ping_results: {}".format(ping_result))
        if not ping_result or ping_result[IP].src != daddr:
            logger.debug("Found sleeping daddr: {}".format(daddr))
            logger.info("Sending WOL, because of packet: {}".format(packet))
            send_wol(hosts[daddr])
    else:
        logger.debug("Skipped - daddr: {}".format(daddr, packet))


def consumer(q, ping_timeout, hosts):
    logger.info("Starting consumer background process")
    we_sent_it_id = b"Sent by NFQ to WOL"
    try:
        with ProcessPoolExecutor() as worker:
            while True:
                pkt = q.get()
                logger.debug("In consumer, got packet: {}".format(pkt))
                if not we_sent_it(pkt, we_sent_it_id):
                    logger.debug("In consumer, starting worker")
                    future = worker.submit(
                        packet_handler, ping_timeout, hosts, pkt, we_sent_it_id
                    )
                    future.result()
                else:
                    logger.info("In consumer, ignoring a packet that we sent")
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt, exiting gracefully.")


@click.command()
@click.option(
    "--config-file",
    type=str,
    default="/etc/nfq-to-wol.yaml",
    help="Path to config file.",
)
@click.option(
    "--ping-timeout", type=float, default=1, help="Timeout for ping checks in seconds."
)
@click.option(
    "--log-level",
    type=click.Choice(
        "DEBUG INFO WARNING ERROR CRITICAL".split(), case_sensitive=False
    ),
    default="WARNING",
    help="Log level for output.",
)
def main(config_file, ping_timeout, log_level):
    logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level.upper())
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

    q = SimpleQueue()
    p = Process(target=consumer, args=(q, ping_timeout, hosts))
    p.start()

    sniff_filter = "dst net {hosts}".format(hosts=" or ".join(hosts))
    logger.info("Using filter: {}".format(sniff_filter))

    sniff(filter=sniff_filter, prn=q.put, store=False)


if __name__ == "__main__":
    main()
