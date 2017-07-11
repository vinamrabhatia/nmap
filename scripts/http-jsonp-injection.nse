local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"
local url = require "url"
local httpspider = require "httpspider"

description = [[
Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be
used to bypass Same-origin Policy restrictions in web browsers.

The script searches for callback functions in the response to detect JSONP
endpoints. It also tries to determine callback function through URL(callback 
function may be fully or partially controllable from URL) and also tries to 
bruteforce the most common callback variables through the URL.

References : https://securitycafe.ro/2017/01/18/practical-jsonp-injection/

]]

---
-- @usage
-- nmap -p 80 --script http-jsonp-detection <target>
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-jsonp-injection: 
-- |   JSONP endpoint found at /rest/contactsjp.php. Function name is callback
-- |_  Callback function is completely controllable from the URL
-- 
--
-- @xmloutput
-- <table>
-- <elem>JSONP endpoint found at /rest/contactsjp.php. Function name is callback</elem>
-- <elem>Callback function is completely controllable from the URL</elem>
-- </table>
-- 
-- @args http-jsonp-detection.path The URL path to request. The default path is "/".
--- 

author = {"Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {""} --to be figured out!

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local callbacks = {"cb", "jsonp", "jsonpcallback", "jcb", "call"}

--Checks the body and returns if valid json data is present in callback function
local checkjson = function(body)
   
  local func, json_data
  _, _, func, json_data = string.find(body, "(%S+)%((.*)%)")  --Check this!

  --Check if the json_data is valid
  --If valid, we have a JSONP endpoint with func as the function name

  local status, json = json.parse(json_data)
  return status, func
end

--Checks if the callback function is controllable from URL
local callback_url = function(host, port, target)
  local path, response, report
  path = target .. "?callback=testing"
  response = http.get(host, port, path)
  if response and response.body and response.status==200 then

    local status, func
    status, func = checkjson(response.body)

    if status == true then
      if func == "testing" then
        report = "Callback function is completely controllable from the URL"
      else
        local p = string.find(func1, "testing")
        if p then 
          report = "Callback function is partially controllable from URL"
        end
      end
    end
  end
  return report
end

--The function tries to bruteforce through the most common callback variable
local callback_bruteforce = function(host, port, target)
  local response, path, report
  for _,p in ipairs(callbacks) do 
    path = target
    path = path .. "?" .. p .. "=test"
    response = http.get(host, port, path)
    if response and response.body and response.status==200 then 

      local status, func
      status, func = checkjson(response.body)

      if status == true then  
        report = "JSONP endpoint found at " .. path .. ". Callback variable is " .. p
        break
      end
    end
  end 
  return report
end 

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local output = stdnse.output_table()
  output = {}

  -- crawl to find jsonp endpoints urls
  local crawler = httpspider.Crawler:new(host, port, path, {scriptname = SCRIPT_NAME})

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  while(true) do
    local status, r = crawler:crawl()
    if (not(status)) then
      if (r.err) then
        return stdnse.format_output(false, r.reason)
      else 
        break
      end
    end

    local target = tostring(r.url)
    target = url.parse(target)
    target = target.path 

    -- First we try to get the response and look for jsonp endpoint there 
    if r.response and r.response.body and r.response.status==200 then

      local report, status, func
      status, func = checkjson(r.response.body)

      if status == true then
        --We have found JSONP endpoint
        --Put it inside a returnable table.
        report = "JSONP endpoint found at " .. target .. ". Function name is " .. func
        table.insert(output, report)

        --Try if the callback function is controllable from URL.     
        report = callback_url(host, port, target)        
        if report ~= nil then
          table.insert(output,report)
        end

      else 

        --Try to bruteforce through most comman callback URLs
        report = callback_bruteforce(host, port, target)
        if report ~= nil then
          table.insert(output,report)
        end
      end 

    end 

  end

  --A way to print returnable 
  if next(output) then
    return output
  else
    return "Couldn't find any JSONP endpoints."
  end 

end 