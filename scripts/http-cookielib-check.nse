local bin = require "bin"
local os = require "os"
local datetime = require "datetime"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"
local httpcookies = require "httpcookies"


--[[
1. new - working
2. parse- working, check with more attributes
3. merge_cookie_table - working, check with more attributes (
4. no_cookie_overwriet - working 
5. get (done)

7. add_cookie - working
8. update_cookie - working 
9. delete_cookie - working
10. get_cookie - working

Test all cases when you pass nil! : --Every function!!(Done)
parse more extensively!!
get more extensively!!(
]]--

description = [[
fdsd
]]


---



author = "HDH"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)

  local cookiejar = {}

  table.insert(cookiejar, {name = "Yup", value = "Yeah"}) 
  --Adding new cookie.

  local cookie = httpcookies.CookieJar:new(cookiejar)

  for k,v in pairs(cookie.cookies) do
    print(k,v)
  end

  print("New Object with cookie above")

  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end

  cookie:add_cookie({name = "Yup1", value = "Yeah1"})
  cookie:add_cookie({name = "Yup2", value = "Yeah2"})
  cookie:add_cookie({name = "Yup3", value = "Yeah3"})
  cookie:add_cookie({name = "Yup4", value = "Yeah4"})

  for k,v in pairs(cookie.cookies) do
    print(k,v)
  end

  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end

  print("Testing add cookie fucntion")

  local status, c = cookie:get_cookie("Yup4")
  print(status)
  for k,v in pairs(c) do
    print(k,v)
  end

  print("Testing get_cookie fucntion")

  cookie:delete_cookie("Yup3")

  for k,v in pairs(cookie.cookies) do
    print(k,v)
  end

  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end

  print("Testing delete_cookie  fucntion")

  cookie:update_cookie({name = "Yup2", value = "Yeah22"})

  local status = cookie:delete_cookie()

  print(status)
  print("tested with nil values")

  for k,v in pairs(cookie.cookies) do
    print(k,v)
  end

  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end

  print("Testing update_cookie  fucntion")

  cookie:set_no_cookie_overwrite(true)

  print(cookie.options.no_cookie_overwrite)
  print("Testing set_no_cookie_overwrite")

  local response = cookie:get(host, port, '/')
  for k,v in pairs(response) do 
    --for kk,vv in pairs(v) do
      print(k,v)
    --end
  end
  print("Testing get") --Working now

  print("All COokies")
  print("Testing weather new cookies were parsed")

  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end
 --New cookies obtained are being added to the library.

  cookie:set_no_cookie_overwrite()

  print(cookie.options.no_cookie_overwrite)
  print("Testing set_no_cookie_overwrite")

  --Parsing cookie with same name and checking if the value gets updated?
  cookie:add_cookie({name = "Yup1", value = "Yeahyeah1"})
  --So, merge cookie updates when same name cookie is passed!
  for k,v in pairs(cookie.cookies) do
    for kk,vv in pairs(v) do
      print(kk,vv)
    end
  end

end

