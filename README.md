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

* ``/etc/xmppoke-queue`` volume which hosts
  the
  [XMPPoke Queue Manager](https://github.com/horazont/xmppoke-queue/blob/master/xmppoke_queue.py) config.

  See the linked repository for config hints. The configuration file is expected
  in ``/etc/xmppoke-queue/config.ini``.

* The XMPPoke Queue Manager is the command which is run by default when running
  the image as a container.
