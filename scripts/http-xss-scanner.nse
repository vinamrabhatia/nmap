local http = require "http"
local httpspider = require "httpspider"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"
local vulns = require "vulns"

description = [[
Spiders an HTTP server looking for forms and  urls and tries to 
determine if they are vulnerable to XSS attacks.

The script works in two parts. It spiders the HTTP server looking 
for forms in the response using http.grab_forms. It also looks for 
*places* where content is being reflected back to the user. It then
injects crafted payloads into the forms and the url and searches 
the response body to check if the payloads were successful.
Successful payloads indicates that website is vulnerable to XSS.

References : https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)

]]

---
-- @usage nmap -p80 --script http-xss-scanner.nse <target>
--
-- @args http-xss-scanner.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-xss-scanner.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-xss-scanner.payloads The path of a plain text file
--       that contains one XSS vector per line. 
--       The default file is nselib/data/http-xss-payloads.lst
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-xss-scanner:
-- |   VULNERABLE:
-- |   Reflection of certain payloads in GET and POST requests indicates XSS Vulnerability.
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       Forms and URLs arent handling certain payloads properlyy resulting in XSS vulnerability.
-- |
-- |     Payloads which got reflected:
-- |     
-- |     References:
-- |        https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet'
--
-- @see http-dombased-xss.nse
-- @see http-phpself-xss.nse
-- @see http-unsafe-output-escaping.nse
---

author = {"George Chatzisofroniou", "Martin Holst Swende", "Vinamra Bhatia" }
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

portrule = shortport.http

local payloads = {}

-- Create customized requests for all of our payloads.
local makeRequests = function(host, port, submission, fields, fieldvalues)

  local postdata = {}
  for _, p in ipairs(payloads) do
    for __, field in ipairs(fields) do
      if field["type"] == "text" or field["type"] == "textarea" or field["type"] == "radio" or field["type"] == "checkbox" then

        local value = fieldvalues[field["name"]]
        if value == nil then
          value = p.vector
        end

        postdata[field["name"]] = value

      end
    end

    stdnse.debug2("Making a POST request to " .. submission .. ": ")
    for i, content in pairs(postdata) do
      stdnse.debug2(i .. ": " .. content)
    end
    local response = http.post(host, port, submission, { no_cache = true }, nil, postdata)
  end

end

local checkPayload = function(body, p)

  if (body:match(p)) then
    return true
  end

end

-- Check if the payloads were successful by checking the content of pages in the uploadspaths array.
local checkRequests = function(body, target)
  local output = {}
  for _, p in ipairs(payloads) do
    if checkPayload(body, p.vector) then
      local report = " Payload: " .. p.vector .. "\n\t Uploaded on: " .. target
      if p.description then
        report = report .. "\n\t Description: " .. p.description
      end
      table.insert(output, report)
    end
  end
  return output
end

local readFromFile = function(payload)
  local f = nmap.fetchfile(payload)
  if f then 
    for l in io.lines(payload) do
      table.insert(payloads, { vector = l })
    end
  end
end

local getHostPort = function(parsed)
  return parsed.host, parsed.port or url.get_default_port(parsed.scheme)
end

local getReflected = function(parsed, r)
  local reflected_values,not_reflected_values = {},{}
  local count = 0
  -- Now, we need to check the parameters and keys
  local q = url.parse_query(parsed.query)
  -- Check the values (and keys) and see if they are reflected in the page
  for k,v in pairs(q) do
    if r.response.body and r.response.body:find(v, 1, true) then
      stdnse.debug2("Reflected content %s=%s", k,v)
      reflected_values[k] = v
      count = count +1
    else
      not_reflected_values[k] = v
    end
  end
  if count > 0 then
    return reflected_values,not_reflected_values,q
  end
end

local createMinedLinks = function(reflected_values, all_values)
  local new_links = {}
  for _,p in pairs(payloads)
    for k,v in pairs(reflected_values) do
      -- First  of all, add the payload to the reflected param
      local urlParams = { [k] = v .. p.vector}
      for k2,v2 in pairs(all_values) do
        if k2 ~= k then
          urlParams[k2] = v2
        end
      end
      new_links[k] = url.build_query(urlParams)
    end
  return new_links
end

local visitLinks = function(host, port,parsed,new_links, returntable,original_url)
  for k,query in pairs(new_links) do
    local ppath = url.parse_path(parsed.path or "")
    local url = url.build_path(ppath)
    if parsed.params then url = url .. ";" .. parsed.params end
    url = url .. "?" .. query
    stdnse.debug2("Url to visit: %s", url)
    local response = http.get(host, port, url)
    for _,p in pairs(payloads) do
      if resonse.body::find(p.vector) then table.insert(returntable, ("[%s] reflected in parameter %s at %s"):format(p, k, original_url))
      --Append one after the another..
    end
  end
end

action = function(host, port)
  local payload = stdnse.get_script_args("http-xss-scanner.payload") or 'nselib/data/http-xss-payload.lst'

  readFromFile(payload)

  local returntable = {}
  local result

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME,  no_cache = true} )

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  local vuln = {
       title = 'Reflection of certain payloads in GET and POST requests indicates XSS Vulnerability.',
       state = vulns.STATE.NOT_VULN,
       description = [[
Forms and URLs arent handling certain payloads properlyy resulting in XSS vulnerability.
       ]],
       references = {
           'https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet'
       }
     }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  --payloads is the table 
  --results have to be in returnable table.
  local index, k, target, response

  -- Phase 1. Crawls through the website and POSTs malicious payloads.
  while (true) do

    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    target = tostring(r.url)
    response = r.response

    if response.body then

      local forms = http.grab_forms(response.body)

      for i, form in ipairs(forms) do

        form = http.parse_form(form)

        if form and form.action then

          local action_absolute = string.find(form["action"], "https*://")

          -- Determine the path where the form needs to be submitted.
          local submission
          if action_absolute then
            submission = form["action"]
          else
            local path_cropped = string.match(target, "(.*/).*")
            path_cropped = path_cropped and path_cropped or ""
            submission = path_cropped..form["action"] 
          end

          makeRequests(host, port, submission, form["fields"], fieldvalues)

        end
      end
    end
    if (index) then
      index = index + 1
    else
      index = 1
    end

    -- parse the returned url
    -- handling the GET requests
    local parsed = url.parse(tostring(r.url))
    -- We are only interested in links which have parameters
    if parsed.query and #parsed.query > 0 then
      local host, port = getHostPort(parsed)
      local reflected_values,not_reflected_values,all_values = getReflected(parsed, r)

      -- Now,were any reflected ?
      if  reflected_values then
        -- Ok, create new links with payloads in the reflected slots
        local new_links = createMinedLinks(reflected_values, all_values)

        -- Now, if we had 2 reflected values, we should have 2*(#payloads) links to fetch
        visitLinks(host, port,parsed, new_links, results,tostring(r.url))
      end
    end

  end

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME } )
  local index

  -- Phase 2. Crawls through the website and searches for the special crafted strings that were POSTed before.
  while true do

    local status, r = crawler:crawl()
    -- if the crawler fails it can be due to a number of different reasons
    -- most of them are "legitimate" and should not be reason to abort
    if ( not(status) ) then
      if ( r.err ) then
        return stdnse.format_output(false, r.reason)
      else
        break
      end
    end

    target = tostring(r.url)
    response = r.response

    if response.body then

      result = checkRequests(response.body, target)

      if next(result) then
        table.insert(returntable, result)
      end
    end
    if (index) then
      index = index + 1
    else
      index = 1
    end
  end

  if ( #returnable > 0 ) then
    vuln.state = vulns.STATE.EXPLOIT
    vulnpages.name = "Payloads which got reflected"
    vuln.extra_info = stdnse.format_output(true, returnable)..crawler:getLimitations()
  end

  return vuln_report:make_output(vuln)

end