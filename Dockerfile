FROM debian:stretch
MAINTAINER Jonas Wielicki <jonas@wielicki.name>

ENV DEBIAN_FRONTEND noninteractive

VOLUME ["/etc/xmppoke-queue"]

RUN apt-get update && apt-get -y dist-upgrade && apt-get install -y --no-install-suggests lua5.1 mercurial build-essential git lua5.1-dev libz-dev libunbound-dev lua-dbi-postgresql libidn11-dev lua-socket libunbound2 luajit wget lua-expat

WORKDIR /opt
RUN hg clone http://code.matthewwild.co.uk/squish/
RUN hg clone https://bitbucket.org/xnyhps/xmppoke
RUN git clone https://github.com/PeterMosmans/openssl
RUN hg clone https://hg.prosody.im/0.9/ prosody
RUN hg clone http://code.matthewwild.co.uk/verse/
RUN mkdir xmppoke/util
RUN cd squish && make && make install
RUN cd openssl && ./config --prefix=/usr/local/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 experimental-jpake shared -DOPENSSL_USE_BUILD_DATE && make depend && make && make install
RUN cd prosody && ./configure --with-lua-include=/usr/include/lua5.1 && make && cp util/encodings.so util/hashes.so ../xmppoke/util/
RUN cd xmppoke/luasec && make "INC_PATH=-I/opt/local/include -I/usr/include -I/usr/local/include -I/usr/include/lua5.1" linux && make LUACPATH=/usr/local/lib/lua/5.1 LUAPATH=/usr/local/share/lua/5.1 install
RUN cd xmppoke/luaunbound && CFLAGS=-I/usr/include/lua5.1 make && make LUA_LIBDIR=/usr/local/lib/lua/5.1/ install && cp lunbound.so ../util/
RUN cd verse && ./configure && make && make install
RUN ln -s /opt/verse /usr/local/share/lua/5.1/
RUN cd xmppoke && squish --use-http --no-minify --debug
RUN cd xmppoke && sed -ri '1s/^(.*)$/_G.socket = require"socket"\n\1/' xmppoke.lua
RUN apt-get remove -y build-essential lua5.1-dev libz-dev libunbound-dev libidn11-dev && apt-get -y autoremove && apt clean
RUN apt-get install -y --no-install-suggests python-twisted
RUN git clone https://github.com/horazont/xmppoke-queue --depth 1

CMD /usr/bin/python2 /opt/xmppoke-queue/xmppoke_queue.py -c /etc/xmppoke-queue/config.ini
