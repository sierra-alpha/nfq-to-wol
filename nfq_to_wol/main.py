from click.core import ParameterSource
from scapy.all import *
import click
from logging.handlers import QueueHandler
import logging
import yaml
import signal
from multiprocessing import Queue, Process, Pool, Manager


def logger_process(log_q, log_level="DEBUG"):
    # Ignore keyboard interrupt we handle this from the main process.
    s = signal.signal(signal.SIGINT, signal.SIG_IGN)
    root = logging.getLogger()
    h = logging.StreamHandler()
    f = logging.Formatter(
        "%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s"
    )
    h.setFormatter(f)
    root.addHandler(h)
    root.setLevel(log_level.upper())
    root.debug("Started logger process.")
    while True:
        record = log_q.get()
        if record is None:
            break
        logger = logging.getLogger(record.name)
        logger.handle(record)
    signal.signal(signal.SIGINT, s)


def make_log_name(log_name=None):
    return "{}{}".format(__name__, "-{}".format(log_name) if log_name else "")


def create_logger(log_q, log_level="DEBUG", log_name=None):
    logger = logging.getLogger(make_log_name(log_name))
    h = QueueHandler(log_q)
    if not len(logger.handlers):
        logger.addHandler(h)
    logger.setLevel(log_level.upper())
    return logger


def load_config(file_path):
    with open(file_path, "r") as stream:
        return yaml.safe_load(stream) or {}


# Credit to the GitHub user @remcohaszing for the pywakeonlan package for
# inspiration on this bit of code.
#
def send_wol(mac_address):
    logger = logging.getLogger(__name__)
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
    logger = logging.getLogger(__name__)
    load = Raw in packet and packet[Raw].load
    result = load == we_sent_it_id
    logger.debug("In we_sent_it, Raw load is {}, we_sent_it? {}".format(load, result))
    return result


# add things about only for a given host
def drain_queue_conditionally(q, hosts, drain_host_ip=None, drain_all=False):
    logger = logging.getLogger(__name__)
    logger.info("Draining queue of host - drain_host_ip: {}".format(drain_host_ip))
    to_put_back_on_queue = []
    while not q.empty():
        packet = q.get()
        logger.debug("Draining queue, found packet - packet {}".format(packet))
        if packet == None or drain_all:
            logger.debug("Draining queue, either drain_all or None received")
            to_put_back_on_queue = [None] if not drain_all else []
            # Drain the queue
            while not q.empty():
                q.get()

            break

        daddr = (
            packet[IP].dst
            if IP in packet
            else packet[ARP].pdst if ARP in packet else "Unknown"
        )
        logger.debug("Draining queue, found daddr - daddr {}".format(daddr))

        # We only want to put packets back on the queue that don't match the
        # host we're draining from the queue (but we also at the same time drop
        # for hosts we don't have config for too).
        #
        if hosts.get(daddr) and daddr != drain_host_ip:
            logger.debug(
                "Draining queue, marking packet to place back on the queue - packet {}".format(
                    packet
                )
            )
            to_put_back_on_queue.append(packet)

    for packet in to_put_back_on_queue:
        logger.debug(
            "Draining queue, putting packet back on the queue - packet {}".format(
                packet
            )
        )
        q.put(packet)

    logger.info("Queue drained of host - drain_host_ip: {}".format(drain_host_ip))


def packet_handler(
    q, ping_timeout, hosts, packet, we_sent_it_id, log_q=Queue(), log_level="DEBUG"
):
    logger = create_logger(log_q, log_level, "packet_handler")
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

            # We only drain the queue on successful ping of a host we're
            # interested in
            #
            drain_queue_conditionally(q, hosts, daddr)
    else:
        logger.debug("Skipped - daddr: {}".format(daddr, packet))
        drain_queue_conditionally(q, hosts)


def consumer(q, ping_timeout, hosts, log_q=Queue(), log_level="DEBUG"):
    # Ignore keyboard interrupt we handle this from the main process.
    s = signal.signal(signal.SIGINT, signal.SIG_IGN)
    logger = create_logger(log_q, log_level, "consumer")
    logger.info("Starting consumer background process")
    we_sent_it_id = b"Sent by NFQ to WOL"

    def raise_x(x):
        raise x

    we_sent_it_id = b"Sent by NFQ to WOL"
    with Pool() as pool:  # start 4 worker processes
        while True:
            pkt = q.get()
            if pkt == None:
                logger.debug("In consumer, recieved packet None exiting.")
                break

            logger.debug("In consumer, got packet: {}".format(pkt))
            if not we_sent_it(pkt, we_sent_it_id):
                logger.debug("In consumer, starting worker")
                pool.apply_async(
                    packet_handler,
                    args=(q, ping_timeout, hosts, pkt, we_sent_it_id),
                    kwds=({"log_q": log_q, "log_level": log_level}),
                    error_callback=raise_x,
                )
            else:
                logger.info("In consumer, ignoring a packet that we sent")

        logger.info("Closing workers.")
        pool.close()
    signal.signal(signal.SIGINT, s)


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
    # Logging setup
    log_q = Manager().Queue()
    logger_p = Process(target=logger_process, args=(log_q, log_level))
    logger_p.start()

    logger = create_logger(log_q, log_level)
    logger.debug("In main Process, logging configured.")

    config_data = load_config(config_file)

    if (
        click.get_current_context().get_parameter_source("ping-timeout")
        == ParameterSource.DEFAULT
    ):
        ping_timeout = config_data.get("ping-timeout", ping_timeout)

    hosts = config_data.get("hosts", {})

    if not hosts:
        log_q.put(None)
        raise ValueError(
            "Requires at lest one host to look for, see template config file "
            "for usage requirements."
        )

    pkt_q = Manager().Queue()
    p = Process(
        target=consumer,
        args=(
            pkt_q,
            ping_timeout,
            hosts,
        ),
        kwargs=({"log_q": log_q, "log_level": log_level}),
    )
    p.start()

    sniff_filter = "dst net {hosts}".format(hosts=" or ".join(hosts))
    logger.info("Using filter: {}".format(sniff_filter))

    try:
        sniff(filter=sniff_filter, prn=pkt_q.put, store=False)
    except KeyboardInterrupt:
        # Close the worker processes
        logger.info("KeyboardInterrupt, exiting.")

    logger.debug("Exiting.")
    drain_queue_conditionally(pkt_q, hosts, drain_all=True)
    pkt_q.put(None)
    p.join()

    logger.info("Consumer finished, closing logging process and exiting.")
    log_q.put(None)


if __name__ == "__main__":
    main()
