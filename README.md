# DNS delegation path traceroute

`ddptr` runs (*i*) UDP traceroutes to all DNS servers that are in the DNS
delegation path for a fully qualified domain name (FQDN), and (*ii*) TCP
traceroutes to port 80 of the same FQDN.  Then, the tool maps the IP addresses
of all intermediate hops to autonomous system numbers and determines the set
intersections.

`ddptr` is useful for traffic analysis experiments, i.e., quantifying the threat
of AS-level adversaries.

Requirements
------------

You will need the Python modules `scapy` and `pyasn`.

Example
-------

The tool takes as input a FQDN and an ASN database.  Instructions on how to
build such a database [are
online](https://github.com/hadiasghari/pyasn#ipasn-data-files).

Here is a simple example:

    $ sudo ./ddptr www.google.com /path/to/asn/database

In my case, the tool tells me:

    8 ASNs in DNS hops: 15169,88,36616,2828,7029,174,27064,3356
    3 ASNs in web hops: 15169,88,174
    3 intersections between web and DNS ASNs: 15169,88,174
    5 ASNs in DNS but not in web ASNs: 27064,7029,36616,2828,3356
    0 ASNs in web but not in DNS ASNs:

You can also use the parameter `--graph-output` to generate traceroute
visualisations such as the following:

![visualisation](https://nullhypothesis.github.com/ddptr-example.png)

Contact
-------
Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
