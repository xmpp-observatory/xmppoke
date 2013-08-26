XMPPoke - Testing the encryption strength of XMPP servers

### Installing

Required:

* luasec with these patches: [https://github.com/xnyhps/luasec/tree/xmppoke](https://github.com/xnyhps/luasec/tree/xmppoke)
* Copy encodings.so from a Prosody build to `util/encodings.so`

Then:

`squish --use-http`

to build xmppoke.lua.

### Running

`lua xmppoke.lua example.com`

This will initiate a number of c2s connections to example.com, to test the TLS configuration.

There's a couple of configuration variables in `poke.lua` that can be changed:

* `use_html`: if true, writes a html formatted report to `reports/example.com.html`.
* `sleep_for`: determines the time between consecutive connection attempts.