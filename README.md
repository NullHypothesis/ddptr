# DNS delegation path traceroute

`ddptr` runs UDP traceroutes to all DNS servers that are in the DNS delegation
path for a particular fully qualified domain name (FQDN).

Example
-------

The tool takes as input a FQDN.  Use the parameter `--graph-output` to write a
traceroute visualisation in SVG format to a file.

    $ sudo ./ddptr www.google.com --graph-output graph.svg

The result looks as follows:

![visualisation](https://nullhypothesis.github.com/ddptr-example.png)

Contact
-------
Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`
