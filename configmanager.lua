local config = { resolvconf = "/etc/resolv.conf", hoststxt = "/etc/hosts" }

return {
get = function(unused, setting)
	return config[setting];
end
}