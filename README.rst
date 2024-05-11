WARNING:
========

At this stage this is very much experimental code, use at your own risk.

NFQ to WOL
===========

NFQ to WOL is a Python program that listens for packets on a network interface
(**not** for now using libnetfilter_queue (NFQ)), and wakes up specified hosts
using Wake-on-LAN (WOL) Magic Packet if they can't be reached by ping within a
specified timeout.

"Wait a minute, you named it 'NFQ to WOL' but it doesn't even use NFQ? What the
...!" Yes, originally I had intended to use libnetfilter_queue bindings and an
nftable filter rule to call a userspace program but during implementation I
discovered Scapy and opted for using that instead. This does have the potential
to impact performance a little bit, so if there is enough interest in this
package I'll look at performance optimisations as the use cases/needs arise.

Why?
----

My use case is that I have a big power hungry, spinning rust, DIY'd NAS and I
like to power it down when not in use, I also have a low power using, Raspberry
Pi, with ample unused SSD storage that is always on, running my K3s cluster. I use
this always on machine to NFS re-export my NAS NFS, so my intention with __NFQ to
WOL__ is to transparently wake the spinning rust server when the always on cache
server needs to access something it doesn't have in the cache, without the users
knowing apart from an initial delay when it first needs to wake the NAS.

Features
--------

- Reads configuration from a YAML file, compulsory for hosts optional for other
  config.
- Listens for incoming packets that match a daddr **not** using NFQ (original
  design was to use libnetfilter_queue but then I found scapy).
- Pings remote host to determine if they are awake (timeout is customisable for
  slower networks).
- If the remote host is sleeping, send a Wake-on-LAN (WOL) magic packet to wake
  up hosts.

Installation
------------

requires, python, tcpdump  and pipx (I think that's it).
Currently only targeting Debian Bookworm, mileage my vary for other platforms.

.. code-block:: bash
   pipx install "git+https://github.com/sierra-alpha/nfq-to-wol"


Usage
-----

NFQ to WOL works at the lower layers of an OS's network stack so it needs to be
run as root to be able to sniff the packets.

NFQ to WOL can be invoked from the command line with optional arguments:

.. code-block:: bash

   nfq-to-wol [--config-file CONFIG_FILE] [--ping-timeout PING_TIMEOUT]

Optional Arguments:

- ``--config-file CONFIG_FILE``: Path to the YAML config file. Default: ``/etc/nfq-to-wol.yaml``.
- ``--ping-timeout PING_TIMEOUT``: Timeout for ping checks in seconds. Default: ``1``.

Configuration
-------------

NFQ to WOL reads configuration from a YAML file. An example configuration file
(`nfq-to-wol.yaml`) is provided:

.. code-block:: yaml

   # Example YAML config file for NFQ to WOL

   # Timeout for ping checks in seconds
   ping_timeout: 2

   # List of hosts with their IP addresses and MAC addresses
   hosts:
     # Example host 1
     192.168.1.10: "00:11:22:33:44:55"
     # Add more hosts as needed

Ensure that the configuration file (`nfq-to-wol.yaml`) is placed in the
appropriate location, such as `/etc/`. You can pass a custom location to the
program with the cli arg `--config-file`.

Service Configuration
---------------------

A systemd service file (`nfq-to-wol.service`) can be used to run NFQ to WOL as a
service:

.. code-block:: plaintext

   [Unit]
   Description=NFQ to WOL
   After=network-online.target

   [Service]
   ExecStart=/usr/local/bin/nfq-to-wol --config /etc/nfq-to-wol.yaml
   Restart=always
   RestartSec=3

   [Install]
   WantedBy=multi-user.target

Ensure that the `ExecStart` path matches the installation path of the
`nfq-to-wol` script.

Limitations
-----------

Only targeting Linux at this stage, specifically Debian Bookworm.
Only targeting IpV4 remote hosts at this stage.


License
-------

This project is licensed under the GNU General Public License v3.0. See the
`LICENSE` file for details.

Contributing
------------

Contributions are welcome! Feel free to open issues or pull requests on the
GitHub repository.

Contact
-------

For any inquiries or support, please contact open an issue.

