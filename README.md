XMPPoke - Testing the encryption strength of XMPP servers

### Installing

Required:

* Install squish from [http://matthewwild.co.uk/projects/squish/home](http://matthewwild.co.uk/projects/squish/home),
* Build luasec from the xmppoke branch of [https://github.com/xnyhps/luasec/tree/xmppoke](https://github.com/xnyhps/luasec/tree/xmppoke),
* Copy encodings.so and hashes.so from `util` in a [Prosody](https://prosody.im) build to `util/` in xmppoke.
* Install luadbi (at least the sqlite3 driver).

Then:

`squish --use-http`

to build xmppoke.lua.

Use:

`sqlite3 results.db < schema.sql`

to initialize the database.

### Running

`lua xmppoke.lua example.com`

This will initiate a number of connections to example.com, to test the TLS configuration.

Usage:

`lua xmppoke.lua [-v] [-h] [--out=reports/] [--mode=(server|client)] [--delay=seconds] hostname`

* `-v`,`--verbose` verbose.
* `-h`,`--html` write a HTML report, instead of ANSI colored output to the terminal.
* `-o`,`--output` the directory where to store the report. Default is **reports/**.
* `-m`,`--mode` the mode (either `client` or `server`). Default is **client**.
* `-d`,`--delay` the number of seconds to wait between every connection. Default is **2**.
* `--capath` path to a directory containing your trusted CA certificates. Default is **/etc/ssl/certs/*.
* `--cafile` path to a directory containing your trusted CA certificates. Default is **nil**.
* `--certificate` path to a client side certificate to use. Some servers refuse s2s connections from servers that use TLS but don't present a client cert. Default is **nil**.
* `--key` path to the private key for the `--certificate`. Default is **nil**.
* `--blacklist` path to the list of keys included in the `openssl-blacklist` package. Default is **/usr/share/openssl-blacklist/**.
