FROM debian:stretch
MAINTAINER Jonas Wielicki <jonas@wielicki.name>

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get -y dist-upgrade && apt-get install -y --no-install-suggests lua5.1 mercurial build-essential git lua5.1-dev libz-dev libunbound-dev lua-dbi-postgresql libidn11-dev lua-socket libunbound2 luajit wget lua-expat python-twisted dns-root-data

WORKDIR /opt
COPY . xmppoke/
WORKDIR /opt/xmppoke/
RUN git clone https://github.com/xnyhps/luasec.git  && cd luasec && git checkout 64bebd9c9283ce11dfa60945938d0a529861d824 && cd ..
RUN hg clone http://code.zash.se/luaunbound/ && cd luaunbound && hg update -r 8356eb09ebaa && cd ..
WORKDIR /opt/
RUN hg clone http://code.matthewwild.co.uk/verse/
RUN mkdir xmppoke/util
RUN hg clone http://code.matthewwild.co.uk/squish/ && cd squish && make && make install && cd .. && rm squish -rf
RUN git clone https://github.com/PeterMosmans/openssl --depth 1 && cd openssl && ./config --prefix=/usr/local/ --openssldir=/etc/ssl enable-zlib enable-ssl2 enable-rc5 enable-rc2 enable-GOST enable-cms enable-md2 enable-mdc2 enable-ec enable-ec2m enable-ecdh enable-ecdsa enable-seed enable-camellia enable-idea enable-rfc3779 enable-ec_nistp_64_gcc_128 experimental-jpake shared -DOPENSSL_USE_BUILD_DATE && make depend && make && make install && cd .. && rm -rf openssl
RUN hg clone https://hg.prosody.im/0.9/ prosody && cd prosody && ./configure --with-lua-include=/usr/include/lua5.1 && make && cp util/encodings.so util/hashes.so ../xmppoke/util/ && cd .. && rm prosody -rf
RUN cd xmppoke/luasec && make "INC_PATH=-I/opt/local/include -I/usr/include -I/usr/local/include -I/usr/include/lua5.1" linux && make LUACPATH=/usr/local/lib/lua/5.1 LUAPATH=/usr/local/share/lua/5.1 install
RUN cd xmppoke/luaunbound && make -B LUA_VERSION=5.1 CFLAGS='-fPIC -I/usr/include/lua5.1 -DIANA_ROOT_TA_FILE=\"/usr/share/dns/root.ds\"' && cp lunbound.so ../
RUN cd verse && ./configure && make && make install
RUN ln -s /opt/verse /usr/local/share/lua/5.1/
RUN cd xmppoke && sed -ri '/local proxy_port/s/9150/9050/;/settimeout/s/5/10/' onions.lua && squish --use-http --no-minify --debug && sed -ri '1s/^(.*)$/_G.socket = require"socket"\n\1/' xmppoke.lua
RUN apt-get install -y --no-install-suggests --no-install-recommends tor
RUN apt-get remove -y build-essential lua5.1-dev libz-dev libunbound-dev libidn11-dev && apt-get -y autoremove && apt clean
RUN git clone https://github.com/horazont/xmppoke-queue --depth 1
COPY docker-entrypoint.sh /

EXPOSE 1337

CMD /docker-entrypoint.sh
