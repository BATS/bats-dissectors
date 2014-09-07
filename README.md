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
available. An older Binary Order Entry (BOE) version 1 dissector is
here which needs clean up and support for version 2 messages.

Requirements
------------

The current code has only been tested with Wireshark 1.12.0 which, at
the time of this writing (September 2014), is the most recently
available version. As Wireshark APIs do periodically change, we assume
it won't work with some previous versions.

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

