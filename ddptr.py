#!/usr/bin/env python
#
# Copyright 2016 Philipp Winter <phw@nymity.ch>
#
# This file is part of dnstracert
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Runs UDP traceroutes to servers in DNS delegation path for a given FQDN.
"""

import os
import re
import sys
import logging as log
import argparse
import subprocess
import collections

import scapy.all as scapy

DIG_OUTPUT_MATCH = r"^;; Received \d+ bytes from ([^\(]+)\([^ ]*\) in \d+ ms$"

Host = collections.namedtuple("Host", "addr port")


def parse_arguments():
    """
    Parse command line arguments.
    """

    desc = "DNS delegation path traceroute"
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument("fqdn", metavar="FQDN", type=str, nargs="+",
                        help="A fully qualified domain name.")

    parser.add_argument("-g", "--graph-output", type=str, default=None,
                        help="Name template of the SVG file that visualises "
                             "the traceroutes.  The name will be prefixed "
                             "with the FQDN.")

    parser.add_argument("-v", "--verbosity", type=str, default="info",
                        help="Minimum verbosity level for logging.  "
                             "Available, in ascending order: debug, info, "
                             "warning, error, critical).  The default is "
                             "`info'.")

    return parser.parse_args()


def traceroute_hosts(hosts, fqdn):
    """
    Run UDP traceroutes to the given hosts, and use FQDN in the DNS requests.
    """

    log.info("Running UDP traceroutes to %d servers." % len(hosts))

    addrs = [host.addr for host in hosts]
    udp_datagram = scapy.UDP(sport=scapy.RandShort())
    dns_msg = scapy.DNS(qd=scapy.DNSQR(qname=fqdn))
    ans, unans = scapy.traceroute(addrs, l4=udp_datagram/dns_msg)

    return ans, unans


def extract_servers(dig_output):
    """
    Extract and return DNS server IP addresses from dig's trace output.
    """

    log.info("Extracting DNS servers from dig's output.")

    hosts = []

    lines = dig_output.split("\n")
    for line in lines:
        match = re.search(DIG_OUTPUT_MATCH, line)
        if match is None:
            continue

        log.debug("Match found: %s" % match.group(1))
        host_tuple = match.group(1).split("#")
        hosts.append(Host(*host_tuple))

    return hosts


def trace_fqdn(fqdn):
    """
    Let dig determine the DNS delegation path for a given FQDN.
    """

    log.info("Tracing delegation path for FQDN: %s" % fqdn)

    try:
        output = subprocess.check_output(["dig", "@8.8.8.8", "+trace", fqdn])
    except Exception as err:
        log.critical(err)
        sys.exit(2)

    return output


def main():
    """
    Entry point.
    """

    args = parse_arguments()
    log.basicConfig(level=log.getLevelName(args.verbosity.upper()))
    log.debug("Set verbosity level to: %s" % args.verbosity)

    if os.geteuid() != 0:
        log.critical("We need root privileges to run traceroutes.")
        return 1

    for fqdn in args.fqdn:

        log.info("Now handling FQDN: %s" % fqdn)

        output_bytes = trace_fqdn(fqdn)
        output = output_bytes.decode("utf-8")
        log.debug("dig output: %s" % output)

        servers = extract_servers(output)
        log.info("DNS servers in dig trace: %s" %
                 ", ".join([h.addr for h in servers]))

        trs, _ = traceroute_hosts(servers, fqdn)
        if args.graph_output is not None:
            file_name = "%s-%s" % (fqdn, args.graph_output)
            trs.graph(target="> %s" % file_name)
            log.info("Wrote traceroute graph to: %s" % file_name)

    return 0

if __name__ == "__main__":
    sys.exit(main())
