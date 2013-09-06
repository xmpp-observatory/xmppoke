XMPPoke - Testing the encryption strength of XMPP servers

### Installing

Required:

* luasec from the xmppoke branch of [https://github.com/xnyhps/luasec/tree/xmppoke](https://github.com/xnyhps/luasec/tree/xmppoke)
* Copy encodings.so and hashes.so from a `util` in a [https://prosody.im](Prosody) build to `util/` in xmppoke.

Then:

`squish --use-http`

to build xmppoke.lua.

### Running

`lua xmppoke.lua example.com`

This will initiate a number of connections to example.com, to test the TLS configuration.

Usage:

`lua xmppoke.lua [-v] [-h] [-o output] [-m (server|client)] [-d=seconds] hostname`

* `-v` verbose.
* `-h` write a HTML report, instead of ANSI colored output to the terminal.
* `-o` the directory to store the report.
* `-m` the mode (either client or server)
* `-d` the number of seconds to wait between every connection.