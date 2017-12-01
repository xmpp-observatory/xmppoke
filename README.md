XMPPoke Docker
==============

What is XMPPoke?
----------------

[XMPPoke](https://bitbucket.org/xnyhps/xmppoke) is a tool which is used to probe
XMPP servers for their security and connectivity settings.
Think [testssl.sh](https://testssl.sh/), but for XMPP and with different features.

It focuses on cipher suites, certificate validity, authentication options, SRV
record setup and DANE.

Usage
-----

Build the docker image as usual.

The docker image exposes the following interface:

* The
  [XMPPoke Queue Manager](https://github.com/horazont/xmppoke-queue/) expects
  some environment variables as configuration. See there for details.

* The XMPPoke Queue Manager is the command which is run by default when running
  the image as a container.
