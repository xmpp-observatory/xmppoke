local ssl = require "ssl"
local dbi = require "DBI"
local date = require "3rdparty/date"
local sql = require "sql"

require "certs"

local sha512 = require("util.hashes").sha512;
local sha256 = require("util.hashes").sha256;

dbh = assert(dbi.Connect("PostgreSQL", "xmppoke", "xmppoke", "xmppoke", "localhost", 5433));

local file = io.open("ca.pem", "r");

local str = file:read("*a");

file:close();

local stm = assert(dbh:prepare("UPDATE certificates SET trusted_root = ?;"));
assert(stm:execute(false));

for cert in str:gmatch("-----BEGIN CERTIFICATE-----\n[^-]*\n-----END CERTIFICATE-----\n") do
	print(ssl.x509.load(cert));
	assert(sql.insert_cert(dbh, ssl.x509.load(cert), nil, nil, nil, true));
end

dbh:commit();