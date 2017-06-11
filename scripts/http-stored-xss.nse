description = [[

Spiders an HTTP server looking for forms and tries to determine
if they are vulnerable to XSS attacks.

The script works in two phases. It spiders an HTTP server looking
for forms in the response using http.grab_forms. It then injects 
crafted payloads into the forms and searches the response body to
check if the payloads were successful.

References : https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)

]]

---
-- @usage nmap -p80 --script http-stored-xss.nse <target>
--
-- @args http-stored-xss.url the url to start spidering. This is a URL
--       relative to the scanned host eg. /default.html (default: /)
-- @args http-stored-xss.maxpagecount the maximum amount of pages to visit.
--       A negative value disables the limit (default: 20)
-- @args http-stored-xss.formpaths The pages that contain
--       the forms to exploit. For example, {/upload.php,  /login.php}.
--       Default: nil (crawler mode on)
-- @args http-stored-xss.uploadspaths The pages that reflect
--       back POSTed data. For example, {/comments.php, /guestbook.php}.
--       Default: nil (Crawler mode on)
-- @args http-stored-xss.fieldvalues The script will try to
--       fill every field found in the form but that may fail due to
--       fields' restrictions. You can manually fill those fields using
--       this table. For example, {gender = "male", email = "foo@bar.com"}.
--       Default: {}
-- @args http-stored-xss.payloads The path of a plain text file
--       that contains one XSS vector per line. 
--       The default file is nselib/data/http-xss-payloads.lst
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-stored-xss:
-- |   Found the following stored XSS vulnerabilities:
-- |
-- |      Payload: ghz>hzx
-- |    Uploaded on: /guestbook.php
-- |    Description: Unfiltered '>' (greater than sign). An indication of potential XSS vulnerability.
-- |      Payload: zxc'xcv
-- |    Uploaded on: /guestbook.php
-- |    Description: Unfiltered ' (apostrophe). An indication of potential XSS vulnerability.
-- |
-- |      Payload: ghz>hzx
-- |    Uploaded on: /posts.php
-- |    Description: Unfiltered '>' (greater than sign). An indication of potential XSS vulnerability.
-- |      Payload: hzx"zxc
-- |    Uploaded on: /posts.php
-- |_   Description: Unfiltered " (double quotation mark). An indication of potential XSS vulnerability.
--
-- @see http-dombased-xss.nse
-- @see http-phpself-xss.nse
-- @see http-xssed.nse
---

categories = {"intrusive", "exploit", "vuln"}
author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local io = require "io"
local string = require "string"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

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
  en
end

action = function(host, port)
  local formpaths = stdnse.get_script_args("http-stored-xss.formpaths")
  local uploadspaths = stdnse.get_script_args("http-stored-xss.uploadspaths")
  local fieldvalues = stdnse.get_script_args("http-stored-xss.fieldvalues") or {}
  local payload = stdnse.get_script_args("http-stored-xss.payload") or 'nselib/data/http-xss-payload.lst'

  readFromFile(payload)

  local returntable = {}
  local result

  for i,v in pairs(payloads) do
    print(i,v)
    for ii,vv in ipairs(v) do
      print(ii,vv)
    end
  end

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME,  no_cache = true} )

  if (not(crawler)) then
    return
  end

  crawler:set_timeout(10000)

  local index, k, target, response

  -- Phase 1. Crawls through the website and POSTs malicious payloads.
  while (true) do

    if formpaths then

      k, target = next(formpaths, index)
      if (k == nil) then
        break
      end
      response = http.get(host, port, target, { no_cache = true, cookie})
      target = host.name .. target
    else

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

    end

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

  end

  local crawler = httpspider.Crawler:new( host, port, '/', { scriptname = SCRIPT_NAME } )
  local index

  -- Phase 2. Crawls through the website and searches for the special crafted strings that were POSTed before.
  while true do
    if uploadspaths then
      k, target = next(uploadspaths, index)
      if (k == nil) then
        break
      end
      response = http.get(host, port, target)
    else

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

    end

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

  if next(returntable) then
    table.insert(returntable, 1, "Found the following stored XSS vulnerabilities: ")
    return returntable
  else
    return "Couldn't find any stored XSS vulnerabilities."
  end
end
