from nfq_to_wol.main import load_config, send_wol, packet_handler, main
from click.testing import CliRunner
from scapy.all import *
import pytest
from pathlib import Path
from unittest.mock import patch, ANY

FIXTURE_DIR = Path(__file__).parent.resolve()
TEST_CONFIG_DATAFILE = pytest.mark.datafiles(FIXTURE_DIR / "test_config.yaml")
MULTI_HOSTS_CONFIG_DATAFILE = pytest.mark.datafiles(FIXTURE_DIR / "multi_hosts_config.yaml")
EMPTY_CONFIG_DATAFILE = pytest.mark.datafiles(FIXTURE_DIR / "empty_config.yaml")


# Check if CLI args overwrite config file values (even if they are the same as
# the default)
@TEST_CONFIG_DATAFILE
def test_cli_args_overwrite_config(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")
    runner = CliRunner()

    with patch("nfq_to_wol.main.sniff") as mock_sniff:
        with patch("nfq_to_wol.main.partial") as mock_partial:
            result = runner.invoke(
                main,
                [
                    "--config-file", str(datafiles / "test_config.yaml"),
                    "--ping-timeout", "1",
                ]
            )

            # Assert that partial function is called with correct arguments
            mock_partial.assert_called_once_with(
                packet_handler, 1, test_config["hosts"]
            )

            # Assert that sniff function is called with correct arguments
            mock_sniff.assert_called_once_with(
                filter="ip dst host 192.168.1.10",
                prn=ANY
            )

# Check that we can deal with multi hosts (and default ping timeout of 1)
@MULTI_HOSTS_CONFIG_DATAFILE
def test_mulitple_hosts_bpf(datafiles):
    multi_hosts_config = load_config(datafiles / "multi_hosts_config.yaml")
    runner = CliRunner()

    with patch("nfq_to_wol.main.sniff") as mock_sniff:
        with patch("nfq_to_wol.main.partial") as mock_partial:
            result = runner.invoke(
                main,
                [
                    "--config-file", str(datafiles / "multi_hosts_config.yaml"),
                ]
            )

            # Assert that partial function is called with correct arguments
            mock_partial.assert_called_once_with(
                packet_handler, 1, multi_hosts_config["hosts"]
            )

            # Assert that sniff function is called with correct arguments
            mock_sniff.assert_called_once_with(
                filter="ip dst host 192.168.1.10 or 192.168.1.11 or 192.168.1.12",
                prn=ANY
            )


# Check if config file with no CLI overides is read in correctly
@TEST_CONFIG_DATAFILE
def test_correct_config_load(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")
    assert test_config == {
        "ping_timeout": 22,
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
            IP(dst="255.255.255.255")
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
        packet = Ether() / ICMP() # not an IP packet
        packet_handler(1, test_config["hosts"], packet)

        # Assert that send function is not called
        assert not mock_sr1.called


# Check if IP packet with dst not in hosts does nothing
@TEST_CONFIG_DATAFILE
def test_ip_packet_dst_not_in_hosts(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate successful ping
    with patch("nfq_to_wol.main.sr1") as mock_sr1:

        # Call packet_handler function with a packet
        packet = Ether() / IP(dst="192.168.1.12") / TCP(dport=80) # not in host file
        packet_handler(1, test_config["hosts"], packet)

        # Assert that send function is not called
        assert not mock_sr1.called


# Check if ping successful does nothing
@TEST_CONFIG_DATAFILE
def test_ping_successful(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate successful ping
    with patch("nfq_to_wol.main.sr1") as mock_sr1:
        mock_sr1.return_value = True  # Simulate successful ping response

        # Mocking send function
        with patch("nfq_to_wol.main.send") as mock_send:
            # Call packet_handler function with a packet
            packet = Ether() / IP(dst="192.168.1.10") / TCP(dport=80)
            packet_handler(1, test_config["hosts"], packet)

            # Assert that send function is not called
            assert not mock_send.called


# Check if ping fails, WOL packet sent
@TEST_CONFIG_DATAFILE
def test_ping_fails_wol_sent(datafiles):
    test_config = load_config(datafiles / "test_config.yaml")

    # Mocking sr1 function to simulate ping failure
    with patch("nfq_to_wol.main.sr1") as mock_sr1:
        mock_sr1.return_value = False  # Simulate failed ping response

        # Mocking send function
        with patch("nfq_to_wol.main.send") as mock_send:
            # Call packet_handler function with a packet
            packet = Ether() / IP(dst="192.168.1.10") / TCP(dport=80)
            packet_handler(1, test_config["hosts"], packet)

            # Assert that send function is called with correct arguments
            mock_send.assert_called_once_with(
                IP(dst="255.255.255.255")
                / UDP(dport=9)
                / Raw(load=bytes.fromhex("FFFFFFFFFFFF" + 16 * "001122334455")),
            )
