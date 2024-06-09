from nfq_to_wol.main import (
    consumer,
    load_config,
    send_wol,
    packet_handler,
    main,
    drain_queue_conditionally,
)
from click.testing import CliRunner
from scapy.all import *
import pytest
from pathlib import Path
from multiprocessing import Manager
from unittest.mock import call, patch

FIXTURE_DIR = Path(__file__).parent.resolve()
TEST_CONFIG_DATAFILE = pytest.mark.datafiles(FIXTURE_DIR / "test_config.yaml")
MULTI_HOSTS_CONFIG_DATAFILE = pytest.mark.datafiles(
    FIXTURE_DIR / "multi_hosts_config.yaml"
)
EMPTY_CONFIG_DATAFILE = pytest.mark.datafiles(FIXTURE_DIR / "empty_config.yaml")

WE_SENT_IT_ID = b"Sent by NFQ to WOL"


# Check if CLI args overwrite config file values (even if they are the same as
# the default), also checks logging process is setup correctly.
@TEST_CONFIG_DATAFILE
def test_cli_args_overwrite_config(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")
    runner = CliRunner()

    with patch("nfq_to_wol.main.sniff") as mock_sniff:
        with patch("nfq_to_wol.main.Manager") as mock_Manager:
            with patch("nfq_to_wol.main.Process") as mock_Process:
                with patch("nfq_to_wol.main.logger_process") as mock_logger_process:
                    with patch("nfq_to_wol.main.consumer") as mock_consumer:
                        result = runner.invoke(
                            main,
                            [
                                "--config-file",
                                str(datafiles / "test_config.yaml"),
                                "--ping-timeout",
                                "1",
                            ],
                        )

                        mock_Process_calls = [
                            # Assert that logging Process function is called
                            # with correct arguments
                            #
                            call(
                                target=mock_logger_process,
                                args=(mock_Manager().Queue(), "WARNING"),
                            ),
                            call().start(),
                            # Assert that Process function is called with
                            # correct arguments
                            #
                            call(
                                target=mock_consumer,
                                args=(
                                    mock_Manager().Queue(),
                                    1.0,
                                    test_config["hosts"],
                                ),
                                kwargs=(
                                    {
                                        "log_q": mock_Manager().Queue(),
                                        "log_level": "WARNING",
                                    }
                                ),
                            ),
                            call().start(),
                            call().join(),
                        ]

                        mock_Process.assert_has_calls(mock_Process_calls)

                        # Assert that sniff function is called with correct
                        # arguments
                        mock_sniff.assert_called_once_with(
                            filter="dst net 192.168.1.10",
                            prn=mock_Manager().Queue().put,
                            store=False,
                        )


# Check that we can deal with multi hosts (and default ping timeout of 1)
@MULTI_HOSTS_CONFIG_DATAFILE
def test_mulitple_hosts_bpf(datafiles):
    multi_hosts_config = load_config(datafiles / "multi_hosts_config.yaml")
    runner = CliRunner()

    with patch("nfq_to_wol.main.sniff") as mock_sniff:
        with patch("nfq_to_wol.main.Manager") as mock_Manager:
            with patch("nfq_to_wol.main.Process") as mock_Process:
                with patch("nfq_to_wol.main.consumer") as mock_consumer:
                    result = runner.invoke(
                        main,
                        [
                            "--config-file",
                            str(datafiles / "multi_hosts_config.yaml"),
                        ],
                    )

                    # Assert that Process function is called with correct arguments
                    mock_Process.assert_called_with(
                        target=mock_consumer,
                        args=(
                            mock_Manager().Queue(),
                            1.0,
                            multi_hosts_config["hosts"],
                        ),
                        kwargs=(
                            {
                                "log_q": mock_Manager().Queue(),
                                "log_level": "WARNING",
                            }
                        ),
                    )

                    # Assert that sniff function is called with correct arguments
                    mock_sniff.assert_called_once_with(
                        filter="dst net 192.168.1.10 or 192.168.1.11 or 192.168.1.12",
                        prn=mock_Manager().Queue().put,
                        store=False,
                    )


# Check if config file with no CLI overides is read in correctly
@TEST_CONFIG_DATAFILE
def test_correct_config_load(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")
    assert test_config == {
        "ping-timeout": 22,
        "hosts": {"192.168.1.10": "00:11:22:33:44:55"},
    }


# Check if config file with no hosts raises ValueError
@EMPTY_CONFIG_DATAFILE
def test_empty_config(datafiles):
    runner = CliRunner()
    result = runner.invoke(
        main, ["--config-file", str(datafiles / "empty_config.yaml")]
    )

    with pytest.raises(ValueError) as exc_info:
        raise result.exception

    assert str(exc_info.value) == (
        "Requires at lest one host to look for, see template config file "
        "for usage requirements."
    )


# Check if we send correctly if called correctly
@pytest.mark.parametrize(
    "mac",
    [
        "00:00:00:00:00:00",
        "10|00|00|00|00|00",
        "2000:0000:0000",
        "300000000000",
    ],
)
def test_valid_mac_address(mac):
    with patch("nfq_to_wol.main.send") as mock_send:
        send_wol(mac)

        mock_send.assert_called_once_with(
            Ether()
            / IP(dst="255.255.255.255")
            / UDP(dport=9)
            / Raw(
                load=bytes.fromhex(
                    "FFFFFFFFFFFF"
                    "{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}{m}".format(
                        m="{}00000000000".format(mac[0])
                    )
                )
            )
        )


# Check if malformed MAC address raises ValueError
def test_malformed_mac_address():
    with pytest.raises(ValueError) as exc_info:
        send_wol("00")

    assert str(exc_info.value) == "Incorrect MAC address format - given: 00"


# Check if non-IP packet does nothing
@TEST_CONFIG_DATAFILE
def test_non_ip_packet(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate successful ping
    with patch("nfq_to_wol.main.sr1") as mock_sr1:

        # Call packet_handler function with a packet
        packet = Ether() / ICMP()  # not an IP packet
        packet_handler(
            Manager().Queue(), 1, test_config["hosts"], packet, WE_SENT_IT_ID
        )

        # Assert that sr1 function is not called
        assert not mock_sr1.called


# Check if IP packet with dst not in hosts does nothing
@TEST_CONFIG_DATAFILE
def test_ip_packet_dst_not_in_hosts(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate successful ping
    with patch("nfq_to_wol.main.sr1") as mock_sr1:

        # Call packet_handler function with a packet
        packet = Ether() / IP(dst="192.168.1.12") / TCP(dport=80)  # not in host file
        packet_handler(
            Manager().Queue(), 1, test_config["hosts"], packet, WE_SENT_IT_ID
        )

        # Assert that sr1 function is not called
        assert not mock_sr1.called


# Check if ping successful does nothing
@TEST_CONFIG_DATAFILE
def test_ping_successful(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate successful ping
    with patch("nfq_to_wol.main.sr1") as mock_sr1:
        # Simulate successful ping response
        mock_sr1.return_value = Ether() / IP(src="192.168.1.10") / ICMP() / "We sent it"

        # Mocking send function
        with patch("nfq_to_wol.main.send") as mock_send:
            # Call packet_handler function with a packet
            packet = IP(dst="192.168.1.10") / TCP(dport=80)
            packet_handler(
                Manager().Queue(), 1, test_config["hosts"], packet, WE_SENT_IT_ID
            )

            # Assert that send function is not called
            assert not mock_send.called


# Check if we originated the ping that we ignore it
@TEST_CONFIG_DATAFILE
def test_self_originated_packet_ignored(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to check it isn't called
    with patch("nfq_to_wol.main.sr1") as mock_sr1:

        # Mocking send function
        with patch("nfq_to_wol.main.send") as mock_send:
            # Call packet_handler function with a packet
            packet = Ether() / IP(src="192.168.1.10") / ICMP() / Raw(load=WE_SENT_IT_ID)
            packet_handler(
                Manager().Queue(), 1, test_config["hosts"], packet, WE_SENT_IT_ID
            )

            # Assert that ping function is not called
            assert not mock_sr1.called

            # Assert that send function is not called
            assert not mock_send.called


# Check if ping fails, WOL packet sent
@TEST_CONFIG_DATAFILE
def test_ping_fails_wol_sent(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate ping failure
    with patch("nfq_to_wol.main.sr1") as mock_sr1:
        mock_sr1.return_value = None  # Simulate failed ping response

        # Mocking send function
        with patch("nfq_to_wol.main.send") as mock_send:
            # Call packet_handler function with a packet
            packet = IP(dst="192.168.1.10") / TCP(dport=80)
            packet_handler(
                Manager().Queue(), 1, test_config["hosts"], packet, WE_SENT_IT_ID
            )

            # Assert that send function is called with correct arguments
            mock_send.assert_called_once_with(
                Ether()
                / IP(dst="255.255.255.255")
                / UDP(dport=9)
                / Raw(load=bytes.fromhex("FFFFFFFFFFFF" + 16 * "001122334455")),
            )


def ip(suffix):
    return "192.168.1.{}".format(suffix)


# Check if we drain q as required
@pytest.mark.parametrize(
    "queue_items,kwargs,result",
    [
        (
            [ip(1), ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": ip(2),
                "drain_all": False,
            },
            [ip(4)],
        ),
        (
            [ip(1), ip(2), ip(3), ip(4), ip(2), ip(2), ip(2), ip(4), ip(2), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": ip(2),
                "drain_all": False,
            },
            [ip(4), ip(4)],
        ),
        (
            [ip(1), ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": ip(2),
                "drain_all": True,
            },
            [],
        ),
        (
            [
                ip(1),
                ip(2),
                ip(3),
                ip(4),
                ip(2),
                ip(1),
                ip(4),
                ip(2),
                ip(2),
                ip(4),
                ip(2),
                ip(5),
            ],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": False,
            },
            [
                ip(2),
                ip(4),
                ip(2),
                ip(4),
                ip(2),
                ip(2),
                ip(4),
                ip(2),
            ],
        ),
        (
            [ip(1), ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": False,
            },
            [ip(2), ip(4)],
        ),
        (
            [ip(1), ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": True,
            },
            [],
        ),
        (
            [ip(1), ip(2), None, ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": False,
            },
            [None],
        ),
        (
            [ip(1), ip(2), None, ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": True,
            },
            [],
        ),
        (
            [None, ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": False,
            },
            [None],
        ),
        (
            [None, ip(2), ip(3), ip(4), ip(5)],
            {
                "hosts": {ip(2): "mock", ip(4): "mock"},
                "drain_host_ip": None,
                "drain_all": True,
            },
            [],
        ),
    ],
)
def test_queue_draining(queue_items, kwargs, result):
    def packet_maker(ip):
        return IP(dst=ip)

    q = Manager().Queue()
    for item in queue_items:
        q.put(packet_maker(item) if item else None)
    drain_queue_conditionally(q, **kwargs)
    result_items = []
    while not q.empty():
        result_item = q.get()
        result_items.append(result_item[IP].dst if result_item else result_item)

    assert result_items == [packet_maker(ip)[IP].dst if ip else ip for ip in result]
