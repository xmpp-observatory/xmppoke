XMPPoke - Testing the encryption strength of XMPP servers

### Installing

Required:

* luasec with these patches: https://github.com/xnyhps/luasec/tree/xmppoke
* Copy encodings.so from a Prosody build to util/encodings.so

Then:

`squish --use-http`

to build xmppoke.lua.

### Running

`lua xmppoke.lua example.com`

This will initiate a number of c2s connections to example.com, to test the TLS configuration.