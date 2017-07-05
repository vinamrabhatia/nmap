local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"

description = [[
Checks for JSONP(JSON with Padding) endpoints in a response and determine
if JSONP injection is possible on the site.

The script searches for callback functions in the response to detect JSONP
endpoints. It also tries to determine callback function through URL(callback 
function may be fully or partially controllable from URL) and also tries to 
bruteforce the most common callback variables through the URL.

References : https://securitycafe.ro/2017/01/18/practical-jsonp-injection/

]]

---
-- @usage
-- nmap -p 80 --script http-jsonp-injection <target>
--
-- @output
-- {{OUTPUT}}
--
-- @xmloutput
--
-- @args http-jsonp-injection.path The URL path to request. The default path is "/".

author = {"Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"", } --to be figured out!

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local response

  response = http.get(host, port, path)

  if response == nil then
    return fail("Request failed")
  end

  if response.body == nil then
    return fail("Response didn't include a proper body.")
  end

  --Getting the response, trying to find callback function with JSON data inside 
  --We need the function name as well as whatever inside.

  local func, json_data

  _, _, func, json_data = string.find(response.body, "(%S+)%((.*)%)") 

  --Check if the json_data is valid?(This checks case 1 and case 2 discussed)
  --If valid, we have a JSONP endpoint with func as the function name.

  local status, json = json.parse(json_data)

  if status == true then
  	--We have found JSONP endpoint
  end

  --Case 3 URL?(Isnt it the same way of testing)

  --Case 4 : Bruteforcing through known URLS? 

end 