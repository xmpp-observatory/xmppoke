local report = nil;


local print_no_nl_html = function(str)
    report:write(str);
    report:flush();
end;

local print_no_nl_ansi = function(str)
    io.stdout:write(str);
end;

local output = {
	html = {
	    boldred = "<span style='color: red; font-weight: bold;'>";
	    red = "<span style='color: red'>";
	    boldgreen = "<span style='color: green; font-weight: bold;'>";
	    green = "<span style='color: green'>";
	    boldblue = "<span style='color: blue; font-weight: bold;'>";
	    reset= "</span>";
	    init = function (path, mode, host)
		    report = io.open(path .. "/" .. mode .. "-" .. host .. ".html", "w");
		    report:write("<html>");
		    report:write("<head>");
		    report:write("<meta http-equiv='Content-Type' content='text/html; charset=UTF-8' />");
		    report:write("<title>XMPP TLS report for " .. host .. "</title>");
		    report:write("</head>");
		    report:write("");
		    report:write("<body>");
		    report:write("<h2>XMPP " .. mode .. "-to-server TLS report for " .. host .. "</h2><b>Date: " .. date() .. "</b><hr />");
		    report:write("<pre>");
		end;
		print = function(str)
		    print_no_nl_html(tostring(str) .. "\n");
		end;
		print_no_nl = print_no_nl_html;
	    finish = function ()
		    report:write("</pre>");
		    report:write("</body>");
		    report:write("</html>");
		end;
		line = function ()
	        report:write("\n<hr />\n");
		end
	};
	ansi = {
	    boldred = string.char(0x1b) .. "[31;1m";
	    red = string.char(0x1b) .. "[31m";
	    boldgreen = string.char(0x1b) .. "[32;1m";
	    green = string.char(0x1b) .. "[32m";
	    boldblue = string.char(0x1b) .. "[34;1m";
	    reset = string.char(0x1b) .. "[0m";
	    init = function () end;
		print = function(str)
		    print_no_nl_ansi(tostring(str) .. "\n");
		end;
		print_no_nl = print_no_nl_ansi;
		finish = function () end;
		line = function()
			print("---");
		end
	}
};

return function (mode)
	return output[mode]
end