"""Linux userspace driver for the Raven Compact Wi-Fi document scanner.

Raven never published the Compact's network protocol. This package talks to
the scanner over the open network-scanning protocols it may implement:

* eSCL (Apple "AirScan" / Mopria), HTTP + XML.
* TWAIN Local, the local-network part of TWAIN Direct (Privet discovery).

``raven-scan probe`` tells you which one your unit speaks.
"""

__version__ = "0.1.0"
