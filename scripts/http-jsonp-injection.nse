local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"
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
-- {{OUTPUT}}
--
-- @xmloutput
--
-- @args http-jsonp-detection.path The URL path to request. The default path is "/".

author = {"Vinamra Bhatia"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {""} --to be figured out!

portrule = shortport.port_or_service({80,443}, "http", "tcp")

local function fail (err) return stdnse.format_output(false, err) end

local callbacks = {"cb", "jsonp", "jsonpcallback", "jcb", "call"}

--Checks the body and returns if valid json data is present in callback function
local checkjson = function(body)
  
  local func, json_data
  _, _, func, json_data = string.find(body, "(%S+)%((.*)%)") 

  --Check if the json_data is valid
  --If valid, we have a JSONP endpoint with func as the function name

  local status, json = json.parse(json_data)
  return status, func
end


action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local output = {}

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

    -- First we try to get the response and look for jsonp endpoint there 
    if r.response and r.response.body and r.response.status==200 then

      local status, func = checkjson(r.response.body)

      if status == true then
        --We have found JSONP endpoint
        --Put it inside a returnable table.
        local report = "JSONP endpoint found. Function name is " .. func
        table.insert(output, report)

        --Try if the callback function is controllable from URL.
        local callback, path, response
        _, _, callback = string.find(target, "%?callback%=(.*)")

        if callback then
          path = string.gsub(path, callback, "testing")
          response = http.get(host, port, path)
          if response and response.body and response.status==200 then

            local status1, fucn1 = checkjson(response.body)

            if status1 == true then
              if func1 == testing then
                local report = "Callback function is completely controllable from the URL"
                table.insert(output, report)
              else
                local p = string.find(func1, "testing")
                if p then 
                  local report = "Callback function is partially controllable from URL"
                  table.insert(output, report)
                end
              end
            end
          end 
        end            

      else 

        --Try to bruteforce through most comman callback URLs
        for _,p in ipairs(callbacks) do 
          local callback, response, path
          path = target
          _, _, callback = string.find(target, "%?(.*)%=")
          if callback == nil then
            path = path .. "?" .. p .. "=test"
          else
            path = string.gsub(path, callback, p)
          end
          response = http.get(host, port, path)
          if response and response.body and response.status==200 then 

            local status1, func1 = checkjson(response.body)

            if status == true and string.find(func1, p) then
              --Put in table : Callback function with valid json found
              --Callback function name is p.
              local report = "Callback function " .. p .. "with JSON data found."
              table.insert(output, report)
              break
            end
          end
        end -- for 
      end --elseif 

    end 

  end

  --A way to print returnable 
  if next(output) then
    return output
  else
    return "Couldn't find any JSONP endpoints."
  end 

end 