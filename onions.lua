
local bit;
pcall(function() bit = require"bit"; end);
if not bit then print("error", "No bit module found. Either LuaJIT 2, lua-bitop or Lua 5.2 is required"); end

local server = require "net.server";


local band = bit.band;
local rshift = bit.rshift;
local lshift = bit.lshift;

local byte = string.byte;
local c = string.char;

local proxy_ip = "127.0.0.1";
local proxy_port = 9150;

function connect_socks5(host_session, connect_host, connect_port)
	local conn, handler = socket.tcp();

	host_session:debug("Connecting to " .. connect_host .. ":" .. connect_port);

	conn:settimeout(5);

	local success, err = conn:connect(proxy_ip, proxy_port);

	if not success then
		host_session:debug(err);
		return false;
	end

	host_session:debug("Connected. Writing handshake...");

	conn:send(c(5) .. c(1) .. c(0));

	host_session:debug("Waiting for result...");

	local data = conn:receive(2);

	-- version, method
	local request_status = byte(data, 2);

	host_session:debug("SOCKS version: "..byte(data, 1));
	host_session:debug("Response: "..request_status);

	if not request_status == 0x00 then
		host_session:debug("Failed to connect to the SOCKS5 proxy. :( It seems to require authentication.");
		return false;
	end

	host_session:debug("Sending connect message.");

	-- version 5, connect, (reserved), type: domainname, (length, hostname), port
	conn:send(c(5) .. c(1) .. c(0) .. c(3) .. c(#connect_host) .. connect_host);
	conn:send(c(rshift(connect_port, 8)) .. c(band(connect_port, 0xff)));

	data = conn:receive(5);

	request_status = byte(data, 2);

	if not request_status == 0x00 then
		host_session:debug("Failed to connect to the SOCKS5 proxy. :(");
		return false;
	end

	host_session:debug("Succesfully connected to SOCKS5 proxy.");
	
	local response = byte(data, 4);

	if response == 0x01 then
		data = data .. conn:receive(5);

		-- this means the server tells us to connect on an IPv4 address
		local ip1 = byte(data, 5);
		local ip2 = byte(data, 6);
		local ip3 = byte(data, 7);
		local ip4 = byte(data, 8);
		local port = band(byte(data, 9), lshift(byte(data, 10), 8));
		host_session:debug("Should connect to: "..ip1.."."..ip2.."."..ip3.."."..ip4..":"..port);

		if not (ip1 == 0 and ip2 == 0 and ip3 == 0 and ip4 == 0 and port == 0) then
			host_session:debug("The SOCKS5 proxy tells us to connect to a different IP, don't know how. :(");
			return false;
		end

		local conn = server.wrapclient(conn, connect_host, connect_port, verse.new_listener(host_session), "*a");
		if not conn then
			host_session:debug("connection initialisation failed", err);
			return false;
		end
		host_session:set_conn(conn);

		return true;
	end

	return false;
end

print("Onions ready and loaded");

return { connect_socks5 = connect_socks5 }