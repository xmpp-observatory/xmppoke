#!/bin/bash
# FIXME: we might want to use something like supervisord here
su debian-tor -s/bin/bash -c /usr/bin/tor &
exec /usr/bin/python2 /opt/xmppoke-queue/xmppoke_queue.py
