bats-dissectors
===============

BATS Global Markets Wireshark Dissectors

Introduction
------------

This project contains Wireshark dissectors for a number of [BATS
Global Markets'](http://www.bats.com/) protocols used in its American
and European equities and options markets.

Protocols Covered
-----------------

Currently, only the Multicast PITCH protocol dissector has been made
available. This covers both the realtime multicast feed, gap multicast
feed, and TCP GRP and Spin protocols.

An older Binary Order Entry (BOE) version 1 dissector is here which
needs to be cleaned up and support for version 2 messages added---it's
not very useful at this time.

Requirements
------------

The current code has only been tested with Wireshark 1.12.0 which, at
the time of this writing (September 2014), is the most recently
available version. As Wireshark APIs do periodically change, we assume
it won't work with some previous versions.

Linux Compilation
-----------------

1. Copy (or symlink) the packet-mcastpitch.c file into the
epan/dissectors directory.

2. Edit epan/dissectors/Makefile.common and add packet-mcastpitch.c to
DISSECTOR_SRC.

3. Rebuild. Note that you'll need GNU automake as the Makefiles will
need to be regenerated.

Testing
-------

Wireshark doesn't have any kind of automated testing framework, so
you'll have to test like it's 1989 by loading up some example files
I've placed in this git repository's pcap subdirectory.

Usage
-----

The Multicast PITCH dissector populates Wireshark's name lookup hash
with hostnames to make it easier to understand what multicast group a
message came from. An example hostname is mcpitch.nj2.u1.u4.rt.za. To
decode this:

* "mcpitch"
* data center from which the message originated: nj2, ny5, or ch4
* low matching unit number
* high matching unit number
* feed type: "rt" (realtime) or "gap" (gap response)
* market + shape: za => (z = BZX, a = GIG A); other markets are y (BYX), a (EDGA), x (EDGX), and o (BZX Options)

Binaries
--------

I expect to make available a Windows installer and RPMs for SuSE Linux
Enterprise Server (SLES) and RedHat Enterprise Linux (RHEL). Stay
tuned.

License
-------

The dissector code is made available under the GPLv2 license. While
some BATS Global Markets employees may contribute to the maintenance
of these dissectors, BATS provides no express or implied warranty for
the code. If you find bugs or have feature requests, reach out to your
usual contacts at BATS and we'll do our best to help.

