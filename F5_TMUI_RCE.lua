function F5_TMUI_RCE (dpimsg, packet)
    -- CVE-2020-5902
    -- reference: https://packetstormsecurity.com/files/158333/BIG-IP-TMUI-Remote-Code-Execution.html
    require 'LOG'
    if packet ~= nil and GetLatestApplication(dpimsg) == "http_proxy" then
      if GetPacketLength(packet) > 0 then
        local http_uri = GetString(dpimsg, "http", "uri_full")
        if string.match(http_uri, "/tmui/login.jsp") ~= nil and string.match(http_uri, ";") ~= nil then
          --SetCustomField(dpimsg, "CVE-2020-5902 BIG-IP-TMUI-Remote-Code-Execution-Attempt", "CVE-2020-5902")
          --EZWARNING("CVE-2020-5902 Attempt")
        end
      end
    end
  end