alias WebSockClose {
  var %Switches, %Error, %Name = $1, %Sock = _WebSocket_ $+ %Name
  if (-* iswm $1) {
    %Switches = $mid($1, 2)
    tokenize 32 $2-
  }
  if ($regex(%Switches, ([^f]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /([f]).*\1/)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($0 > 1) {
    %Error = Excessive parameters
  }
  elseif (!$regex($1, /^(?!\d+$)[^?*-][^?*]*$/)) {
    %Error = Invalid websocket name
  }
  elseif (!$sock(%Sock)) {
    ._WebSocket.Cleanup %Sock
    %Error = WebSocket does not exist
  }
  elseif (f isincs %Switches) {
    ._WebSocket.Cleanup %Sock
  }
  elseif ($hget(%Sock, SOCK_STATE) isnum 1-3) {
    _WebSocket.Cleanup %Sock
  }
  elseif ($hget(%Sock, SOCK_STATE) == 0 || $v1 == 5) {
    %Error = Connection already closing
  }
  elseif ($hget(%Sock, CLOSE_PENDING)) {
    %Error = CLOSE frame already sent
  }
  else {
    WebSockWrite -c $1
  }
  :error
  if ($error || %Error) {
    echo -sg * /WebSockClose: $v1
    reseterror
    halt
  }
}
alias -l _WebSocket.Cleanup {
  var %Name = $gettok($1, 2-, 95)
  if ($sock($1)) {
    sockclose $1
  }
  if ($hget($1)) {
    hfree $1
  }
  .timer_WebSocket_Timeout_ $+ %Name off
  if ($show) {
    .signal -n WebSocket_FINISHED_ $+ %Name
  }
}
on $*:SOCKCLOSE:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95)
  if ($sockerr) {
    %Error = SOCK_ERROR $sock($sockname).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR state lost (hashtable does not exist)
  }
  elseif (!$hget($sockname, state) !== 5) {
    %Error = SOCK_ERROR Connection closed without recieving a CLOSE frame
  }
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    _WebSocket.Debug -e %Name $+ >SOCKCLOSE~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
  else {
    _WebSocket.Debug -s %Name $+ >SOCKCLOSE~Connection Closed
    .signal -n WebSocket_CLOSE_ $+ %Name
  }
  _WebSocket.Cleanup $sockname
}
alias -l _WebSocket.BAdd {
  bset -t $1 $calc($bvar($1, 0) + 1) $2- $+ $crlf
}
alias -l _WebSocket.RaiseError {
  hadd -m $+(_WebSocket_, $1) ERROR $2-
  .signal -n WebSocket_ERROR_ $+ $1
  _WebSocket.Cleanup _WebSocket_ $+ $1
}
alias WebSock {
  if (!$isid) {
    return
  }
  var %Name, %Sock, %State, %Find, %Index, %Header
  if (!$0) {
    if ($event !== signal || !$regex(NameFromSignal, $signal, /^WebSocket_[a-zA-z]+_(?!\d+$)([^?*-][^?*]*)$/i)) {
      return
    }
    %Name = $regml(NameFromSignal, 1)
  }
  elseif ($regex(Name, $1, /^(?!\d+$)([^?*-][^?*]*)$/)) {
    %Name = $regml(Name, 1)
  }
  else {
    return
  }
  %Sock = _WebSocket_ $+ %Name
  if (!$sock(%Sock) && !$hget(%sock)) {
    return
  }
  if (!$prop) {
    return %Name
  }
  elseif ($prop == State) {
    return $hget(%Sock, SOCK_STATE)
  }
  elseif ($prop == StateText) {
    %State = $hget(%Sock, SOCK_STATE)
    if (!$len(%State)) {
      return
    }
    elseif (%State == 0) {
      return CLOSING
    }
    elseif (%State == 1) {
      return INITIALIZED
    }
    elseif (%State == 2) {
      return REQUESTING
    }
    elseif (%State == 3) {
      return RESPONSE_PENDING
    }
    elseif (%State == 4) {
      return READY
    }
    elseif (%State == 5) {
      return CLOSING
    }
  }
  elseif ($prop == Ssl) {
    return $iif($sock(%Sock), $sock(%sock).ssl, $hget(%Sock, SOCK_SSL))
  }
  elseif ($prop == Host) {
    return $iif($sock(%Sock).addr, $v1, $hget(%Sock, SOCK_ADDR))
  }
  elseif ($prop == Port) {
    return $iif($sock(%Sock).port, $v1, $hget(%Sock, SOCK_PORT))
  }
  elseif ($prop == Uri) {
    return $hget(%Sock, HTTPREQ_URI))
  }
  elseif ($prop == HttpVersion) {
    return $hget(%Sock, HTTPRESP_HttpVersion)
  }
  elseif ($prop == StatusCode) {
    return $hget(%Sock, HTTPRESP_StatusCode)
  }
  elseif ($prop == StatusText) {
    return $hget(%Sock, HTTPRESP_StatusText)
  }
  elseif ($prop == HttpHeader) {
    if (!$hget(%Sock) || $0 < 2 || !$len($2) || $0 > 3 || ($0 == 3 && (!$len($3) || $3 !isnum 0- || . isin $3))) {
      return
    }
    elseif ($0 == 2 && . !isin $2) {
      if (!$2) {
        return $hfind(%Sock, /^HTTPRESP_HEADER\d+_/, 0, r)
      }
      return $gettok($hfind(%Sock, ^HTTPRESP_HEADER $+ $2 $+ _, 1, r), 3-, 95)
    }
    else {
      %Index = $iif($0 == 3, $3, 1)
      %Header = $hfind(%Sock, /^HTTPRESP_HEADER\d+_\Q $+ $replacecs($2, \E, \Q\\E\E) $+ \E$/, %Index, r)
      if (!%Index) {
        return %Header
      }
      return $hget(%Sock, %Header)
    }
  }
}
alias WebSockHeader {
  var %Error, %Name, %Sock
  if (!$isid || $event !== signal || !$regex($signal, /^WebSocket_INIT_(?!\d+$)([^?*-][^?*]*)$/i)) {
    return
  }
  else {
    %Name = $regml(name, 1)
    %Sock = _WebSocket_ $+ %Name
    if (!$sock(%Sock)) {
      %Error = WebSocket not in use
    }
    elseif ($0 !== 2) {
      %Error = Missing parameters
    }
    else {
      %Header = $regsubex($1, /(?:^\s)(?:\s*:\s*$)/g, )
      if (!$len(%Header)) {
        %Error = Invalid header name
      }
      else {
        %Index = $calc($hfind(%Sock, ^HTTPREQ_HEADER\d+_, 0, r) + 1)
        hadd -m %Sock $+(HTTPREQ_HEADER, %Index, _, %Header) %Value
      }
    }
  }
  :error
  if ($error || %Error) {
    echo -sg * /WebSockHeader: $v1
    reseterror
    halt
  }
}
alias WebSockType {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/i)) {
    return
  }
  return $hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_TYPE)
}
alias WebSockTypeText {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/i)) {
    return
  }
  var %type = $hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_TYPE)
  if (%type == 1) {
    return TEXT
  }
  elseif (%Type == 2) {
    return BINARY
  }
  elseif (%TYPE == 8) {
    return CLOSE
  }
  elseif (%Type == 9) {
    return PING
  }
  elseif (%Type == 10) {
    return PONG
  }
}
alias WebSockText {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  bunset &_WebSocket_EventFrameData
  if ($hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_DATA, &_WebSocket_EventFrameData)) {
    return $bvar(&_WebSocket_EventFrameData, 1, 3500).text
  }
}
alias WebSockData {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  elseif ($0 == 1 && &?* !iswm $1 && $chr(32) isin $1) {
    if ($bvar($1, 0)) {
      bunset $1
    }
    return $hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_DATA, $1)
  }
}
alias WebSockErr {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_ERROR_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  return $gettok($hget(_WebSocket_ $+ $regml(event, 1), ERROR), 1, 32)
}
alias WebSockErrMsg {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_ERROR_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  return $gettok($hget(_WebSocket_ $+ $regml(event, 1), ERROR), 2-, 32)
}
alias WebSockDebug {
  if ($isid) {
    return $iif($group(#_WebSocket_Debug) == on, $true, $false)
  }
  if ($1 == on || $1 == enable) {
    .enable #_WebSocket_Debug
  }
  elseif ($1 == off || $1 == disable) {
    .disable #_WebSocket_Debug
  }
  elseif (!$0) {
    $iif($group(#_WebSocket_Debug) == on, .disable, .enable) #_WebSocket_Debug
  }
  else {
    echo -gs * /WebSockDebug: Invalid input
    halt
  }
  if ($group(#_WebSocket_Debug) == on && !$window(@WebSocketDebug)) {
    window -nzk0 @WebSocketDebug
  }
}
#_WebSocket_Debug off
alias -l _WebSocket.Debug {
  if (!$window(@WebSocketDebug)) {
    .disable #_WebSocket_Debug
  }
  else {
    var %Color = 12, %Title = WebSocket, %Msg
    if (-* iswm $1) {
      if ($1 == -e)  %Color = 04
      if ($1 == -w)  %Color = 07
      if ($1 == -i)  %Color = 03
      if ($1 == -i2) %Color = 10
      if ($1 == -s)  %Color = 12
      tokenize 32 $2-
    }
    if (~ !isincs $1-) {
      %Msg = $1-
    }
    elseif (~* iswm $1-) {
      %Msg = $mid($1-, 2-)
    }
    else {
      %Title = $gettok($1-, 1, 126)
      %Msg = $gettok($1-, 2-, 126)
    }
    aline @WebSocketDebug $+($chr(3), %Color, [, %Title, ], $chr(15)) %msg
  }
}
#_WebSocket_Debug end
alias -l _WebSocket.Debug
menu @WebSocketDebug {
  $iif($WebSockDebug, Disable, Enable): WebSocketDebug
  -
  Save: noop
  Clear:clear @WebSocketDebug
  -
  Close: .disable #_WebSocket_Debug | close -@ @WebSocketDebug
}
on *:CLOSE:@WebSocketDebug:{
  .disable #_WebSocket_Debug
}
on *:START:{
  if ($WebSockDebug) {
    window -nzk0 @WebSocketDebug
  }
}
on *:UNLOAD:{
  sockclose _WebSocket_*
  hfree -w _WebSocket_
  .timer_WebSocket_Timeout_* off
  if ($Window(@WebSocketDebug)) {
    close -@ @WebSocketDebug
  }
}
alias WebSockOpen {
  if ($isid) {
    return
  }
  var %Error, %Sock, %Host, %Ssl, %Port
  if ($0 < 2) {
    %Error = Missing paramters
  }
  elseif ($0 > 3) {
    %Error = Excessive Parameters
  }
  elseif (? isin $1 || * isin $1) {
    %Error = names cannot contain ? or *
  }
  elseif ($1 isnum) {
    %Error = names cannot be a numerical value
  }
  elseif ($sock(WebSocket_ $+ $1)) {
    %Error = specified 'name' in use
  }
  elseif ($0 == 3) && ($3 !isnum 1- || . isin $3 || $3 > 300) {
    %Error = Invalid timeout; must be an integer between 1 and 300
  }
  elseif (!$regex(uri, $2, m ^((?:wss?://)?)([^?&#/\\:]+)((?::\d+)?)((?:[/\\][^#]*)?)(?:#.*)?$ i)) {
    %Error = Invalid URL specified
  }
  else {
    %Sock = _WebSocket_ $+ $1
    %Host = $regml(uri, 2)
    if ($hget(%Sock)) {
      ._WebSocket.Cleanup %Sock
    }
    if (wss:// == $regml(uri, 1)) {
      %Ssl = $true
    }
    else {
      %Ssl = $false
    }
    if ($regml(uri, 3)) {
      %Port = $mid($v1, 2-)
      if (%Port !isnum 1-65535 || . isin %port) {
        %Error = Invalid port specified in uri; must be an interger to between 1 and 65,535
        goto error
      }
    }
    elseif (%Ssl) {
      %Port = 443
    }
    else {
      %Port = 80
    }
    hadd -m %Sock SOCK_STATE 1
    hadd %Sock SOCK_SSL %Ssl
    hadd %Sock SOCK_ADDR %Host
    hadd %Sock SOCK_PORT %Port
    hadd %Sock HTTPREQ_URI $2
    hadd %Sock HTTPREQ_RES $iif($len($regml(uri, 4)), $regml(uri, 4), /)
    hadd %Sock HTTPREQ_HOST %Host $+ $iif((%Ssl && %Port !== 443) || (!%Ssl && %Port !== 80), : $+ %Port)
    $+(.timer, _WebSocket_Timeout_, $1) -oi 1 $iif($3, $v1, 300) _WebSocket.ConnectTimeout %Name
    sockopen $iif(%ssl, -e) %sock %host %port
    _WebSocket.Debug -i Connecting> $+ $1 $+ ~Connecting to %host $iif(%ssl, with an SSL connection) on port %port as %sock
  }
  :error
  if ($error || %error) {
    echo $color(info).dd -s * /WebSockOpen: $v1
    _WebSocket.Debug -e /WebSockOpen~ $+ $v1
    reseterror
    halt
  }
}
alias -l _WebSocket.ConnectTimeout {
  if ($isid) {
    return
  }
  _WebSocket.Debug -e $1 $+ >TIMEOUT Connection timed out
  _WebSocket.RaiseError $1 SOCK_ERROR Connection timout
}
on $*:SOCKOPEN:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %Key, %Index
  _WebSocket.Debug -i2 SockOpen> $+ $sockname $+ ~Connection established
  if ($sockerr) {
    %Error = SOCKOPEN_ERROR $sock($socknamw).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR socket-state hashtable doesn't exist
  }
  elseif ($hget($sockname, SOCK_STATE) != 1) {
    %Error = INTERNAL_ERROR State doesn't corrospond with connection attempt
  }
  elseif (!$len($hget($sockname, HTTPREQ_HOST))) {
    %Error = INTERNAL_ERROR State table does not contain host name
  }
  elseif (!$len($hget($Sockname, HTTPREQ_RES))) {
    %Error = INTERNAL_ERROR State table does not contain a resource to request
  }
  else {
    _WebSocket.Debug -i SockOpen> $+ %name $+ ~Preparing request head
    bset &_WebSocket_SecWebSocketKey 1 $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255)
    noop $encode(&_WebSocket_SecWebSocketKey, bm)
    hadd -mb $sockname HTTPREQ_SecWebSocketKey &_WebSocket_SecWebSocketKey
    bunset &_WebSocket_SecWebSocketKey &_WebSocket_HttpReq
    _WebSocket.BAdd &_WebSocket_HttpReq GET $hget($sockname, HTTPREQ_RES) HTTP/1.1
    _WebSocket.BAdd &_WebSocket_HttpReq Host: $hget($sockname, HTTPREQ_HOST)
    _WebSocket.BAdd &_WebSocket_HttpReq Connection: upgrade
    _WebSocket.BAdd &_WebSocket_HttpReq Upgrade: websocket
    _WebSocket.BAdd &_WebSocket_HttpReq Sec-WebSocket-Version: 13
    _WebSocket.BAdd &_WebSocket_HttpReq Sec-WebSocket-Key: $hget($sockname, HTTPREQ_SecWebSocketKey)
    .signal -n WebSocket_INIT_ $+ %Name
    %Index = 1
    while ($hfind($sockname, /^HTTPREQ_HEADER\d+_([^\s]+)$/, %Index, r)) {
      _WebSocket.BAdd &_WebSocket_HttpReq $regml(1) $hget($sockname, $v1)
      inc %Index
    }
    _WebSocket.BAdd &_WebSocket_HttpReq
    hadd -b $sockname HTTPREQ_HEAD &_WebSocket_HttpReq
    bunset &_WebSocket_HttpReq
    hadd $sockname SOCK_STATE 2
    _WebSocket.Debug -i SockOpen> $+ %Name $+ ~Sending HTTP request
    _WebSocket.Send $sockname
  }
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    %Error = $v1
    reseterror
    _WebSocket.Debug -e SockOpen> $+ %Name $+ ~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}
on $*:SOCKREAD:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %HeadData, %Index, %SecAccept, %HeadSize, %FragSize
  if ($sockerr) {
    %Error = SOCKREAD_ERROR $sock($sockname).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR State lost
  }
  elseif ($hget($sockname, SOCK_STATE) == 5) {
    %Error = FRAME_ERROR Frame recieved after a CLOSE frame has been recieved.
  }
  elseif ($v1 == 3) {
    if (!$hget($sockname, HTTPREQ_SecWebSocketKey)) {
      %Error = INTERNAL_ERROR State lost (Sec-WebSocket-Key Not Found)
    }
    else {
      sockread %HeadData
      while ($sockbr) {
        %HeadData = $regsubex(%HeadData, /(?:^\s+)|(?:\s+$)/g, )
        if (%HeadData) {
          if (!$len($hget($sockname, HTTPRESP_StatusCode))) {
            if ($regex(%HeadData, /^HTTP\/(0\.9|1\.[01]) (\d+)((?:\s.*)?)[\r\n]*$/i)) {
              hadd $sockname HTTPRESP_HttpVersion $regml(1)
              hadd $sockname HTTPRESP_StatusCode $regml(2)
              hadd $sockname HTTPRESP_StatusText $iif($regml(3), $v1, _NONE_)
            }
            else {
              %Error = HTTP_ERROR Status line invalid: %HeadData
            }
          }
          elseif ($regex(header, %HeadData, ^(\S+): (.*)$)) {
            %Index = $calc($hfind($sockname, HTTPRESP_HEADER?*_*, 0, w) + 1)
            hadd $sockname $+(HTTPRESP_HEADER, %Index, _, $regml(header, 1)) $regml(header, 2)
            _WebSocket.Debug -i %Name $+ >HEADER~Header Received: $regml(header, 1) $+ : $regml(header, 2)
          }
          else {
            %Error = HTTP_ERROR Response contained an invalid header
          }
        }
        elseif ($hget($sockname, HTTPRESP_HttpVersion) !== 1.1) {
          %Error = HTTP_ERROR Unacceptable HTTP version: $v1
        }
        elseif ($hget($sockname, HTTPRESP_StatusCode) !== 101) {
          %Error = HTTP_ERROR Response does not wish to upgrade
        }
        elseif ($hfind($sockname, HTTPRESP_Header?*_Connection, 1, w) == $null || $hget($sockname, $v1) !== Upgrade) {
          %Error = HTTP_ERROR Connection header not received or not "Upgrade"
        }
        elseif ($hfind($sockname, HTTPRESP_Header?*_Upgrade, 1, w) == $null || $hget($sockname, $v1) !== websocket) {
          %Error = HTTP_ERROR Upgrade header not received or not "websocket"
        }
        elseif ($hfind($sockname, HTTPRESP_Header?*_Sec-WebSocket-Accept, 1, w) == $null) {
          %Error = HTTP_ERROR Sec-WebSocket-Accept header not received
        }
        else {
          %SecAccept = $hget($sockname, $v1)
          bset -c &_WebSocket_SecWebSockAccept 1 $regsubex($sha1($hget($sockname, HTTPREQ_SecWebSocketKey) $+ 258EAFA5-E914-47DA-95CA-C5AB0DC85B11), /(..)/g, $base(\t, 16, 10) $+ $chr(32))
          noop $encode(&_WebSocket_SecWebSockAccept, mb)
          if (%SecAccept !== $bvar(&_WebSocket_SecWebSockAccept, 1-).text) {
            %Error = HTTP_ERROR Sec-WebSocket-Accept header value does not match digested key
          }
          else {
            $+(.timer, _WebSocket_Timeout_, %Name) off
            hadd $sockname SOCK_STATE 4
            _WebSocket.Debug -s %Name $+ >HANDSHAKE~Handshake complete; ready to send and recieve frames!
            .signal -n WebSocket_READY_ $+ %Name
          }
        }
        if (%Error || $hget($sockname, SOCK_STATE) == 4) {
          break
        }
        sockread %HeadData
      }
    }
  }
  elseif ($hget($sockname, SOCK_STATE) == 4) {
    bunset &_WebSocket_ReadBuffer &_WebSocket_RecvData
    sockread $sock($sockname).rq &_WebSocket_RecvData
    if ($hget($sockname, WSFRAME_PENDING, &_WebSocket_ReadBuffer)) {
      bcopy -c &_WebSocket_ReadBuffer $calc($bvar(&_WebSocket_ReadBuffer, 0) + 1) &_WebSocket_RecvData 1 -1
    }
    else {
      bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_RecvData 1 -1
    }
    bunset &_WebSocket_RecvData
    hdel $sockname WSFRAME_DATA
    hdel $sockname WSFRAME_TYPE
    while ($bvar(&_WebSocket_ReadBuffer, 0) >= 2) {
      %HeadData = $bvar(&_WebSocket_ReadBuffer, 1, 1)
      %HeadSize = 2
      %FragSize = $bvar(&_WebSocket_ReadBuffer, 2, 1)
      if ($hget($sockname, SOCK_STATE) == 5) {
        %Error = FRAME_ERROR Frame recieved after a CLOSE frame has been recieved.
      }
      elseif ($isbit(%HeadData, 5) || $isbit(%HeadData, 6) || $isbit(%HeadData, 7)) {
        %Error = FRAME_ERROR Frame used RSV bits
      }
      elseif (!$isbit(%HeadData, 8) && $calc(%HeadData % 128) isnum 8-10) {
        %Error = FRAME_ERROR Fregmented control frame
      }
      elseif ($isbit(%HeadData, 4) && %HeadData !isnum 136-138) {
        %Error = FRAME_ERROR Recieved unknown control-frame type
      }
      elseif (!$isbit(%HeadData, 4) && $calc(%HeadData % 128) !isnum 1-2) {
        %Error = FRAME_ERROR Received unknown data-frame type
      }
      elseif ($isbit(%FragSize, 8)) {
        %Error = FRAME_ERROR Received masked frame from server
      }
      elseif (!$isBit(%HeadData, 4) && $hget($sockname, WSFRAME_FragmentType) && $v1 !== $calc(%HeadData % 128)) {
        %Error = FRAME_ERROR Recieved Mixed frame data-type fragments
      }
      elseif (%FragSize == 127 && $bvar(&_WebSocket_ReadBuffer, 0) >= 6 && $bvar(&_WebSocket_ReadBuffer, 3).nlong !== 0) {
        %Error = FRAME_ERROR Data size would overflow an int32
      }
      else {
        if (%FragSize == 126) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 4) {
            break
          }
          %HeadSize = 4
          %FragSize = $bvar(&_WebSocket_ReadBuffer, 3, 2).nword
        }
        elseif (%DataSize == 127) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 10) {
            break
          }
          %HeadSize = 10
          %FragSize = $bvar(&_WebSocket_ReadBuffer, 7).nlong
        }
        if ($bvar(&_WebSocket_ReadBuffer, 0) < $calc(%HeadSize + %FragSize)) {
          break
        }
        bunset &_WebSocket_FrameData
        noop $hget($sockname, WSFRAME_Fragment, &_WebSocket_FrameData)
        hdel $sockname WSFRAME_Fragment
        hdel $sockname WSFRAME_FragmentType
        bcopy -c &_WebSocket_FrameData $calc($bvar(&_WebSocket_FrameData, 0) + 1) &_WebSocket_ReadBuffer $calc(%HeadSize + 1) %FragSize
        if ($calc(%HeadSize + %FragSize) == $bvar(&_WebSocket_ReadBuffer, 0)) {
          bunset &_WebSocket_ReadBuffer
        }
        else {
          bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_ReadBuffer $calc($v1 +1) -1
        }
        if ($bvar(&_WebSocket_FrameData, 0)) {
          hadd -mb $sockname WSFRAME_DATA &_WebSocket_FrameData
        }
        else {
          hdel $sockname WSFRAME_DATA
        }
        hadd -m $sockname WSFRAME_TYPE $calc(%HeadData % 128)
        if (%HeadData == 136) {
          if ($bvar(&_WebSocket_ReadBuffer, 0)) {
            %Error = FRAME_ERROR Data recieved after a CLOSE frame has been recieved.
          }
          elseif ($hget($sockname, CLOSE_PENDING)) {
            _WebSocket.Debug -i2 %Name $+ >FRAME:CLOSE~Close frame reply received; closing connection.
            .signal -n WebSocket_CLOSE_ $+ %Name
            _WebSocket.Cleanup $sockname
          }
          else {
            _WebSocket.Debug -i %Name $+ >FRAME:CLOSE~Close frame received.
            .signal -n WebSocket_CLOSING_ $+ %Name %Name
            hadd $sockname SOCK_STATE 5
            WebSockClose %Name
          }
          break
        }
        elseif (%HeadData == 137) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Ping frame received.
          .signal -n WebSocket_PING_ $+ %Name
          WebSockWrite -P %Name &_WebSocket_FrameData
        }
        elseif (%HeadData == 138) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Pong frame received.
          .signal -n WebSocket_PONG_ $+ %Name
        }
        else if (!$isbit(%HeadData, 8)) {
          hadd -b $sockname WSFRAME_Fragment &_WebSocket_FrameData
          hadd $sockname  WSFRAME_FragmentType $calc(%HeadData % 128)
        }
        elseif (%HeadData == 129 || %HeadData == 130) {
          _WebSocket.Debug -i %Name $+ >FRAME:Data~ $+ $iif(%HeadData == 129, Text, Binary) frame recieved
          .signal -n WebSocket_DATA_ $+ %Name
        }
      }
      hdel $sockname WSFRAME_DATA
      hdel $sockname WSFRAME_TYPE
      if (%Error) {
        break
      }
    }
    if (!%Error) {
      if ($bvar(&_WebSocket_ReadBuffer, 0)) {
        hadd -b $sockname WSFRAME_PENDING &_WebSocket_ReadBuffer
      }
      elseif ($hget($sockname, WSFRAME_PENDING).item) {
        hdel $sockname WSFRAME_PENDING
      }
    }
  }
  elseif ($v1 !== 0) {
    %Error = INTERNAL_ERROR State variable mixmatch
  }
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    _WebSocket.Debug -e SockRead> $+ %Name $+ ~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}
alias WebSockWrite {
  if ($isid) {
    return
  }
  var %FrameSwitch, %DataSwitch, %Name, %Sock, %Error, %Control = $false, %Code = 1, %TypeText = TEXT, %BVar = &_WebSocket_FrameData, %BVarUnset = $true, %Index, %Size, %MaskByte1, %MaskByte2, %MaskByte3, %MaskByte4
  if ($left($1, 1) isin +-) {
    noop $regex($1, /^((?:-[^+]*)?)((?:\+.*)?)$/))
    %FrameSwitch = $mid($regml(1), 2)
    %DataSwitch = $mid($regml(2), 2)
    tokenize 32 $2-
  }
  %Name = $1
  %Sock = _WebSocket_ $+ $1
  if ($regex(%FrameSwitch, ([^cpPbt]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?\1)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?([cpPbt]))) {
    %Error = Conflicting switches: $regml(1) $regml(2)
  }
  elseif ($regex(%DataSwitch, ([^t]))) {
    %Error = Invalid Data-force switch + $+ $regml(1)
  }
  elseif (!$regex($1, ^(?!\d+$)[^?*]+$) || !$sock(%Sock)) {
    %Error = WebSocket does not exist
  }
  elseif (!$hget(%Sock) || !$len($hget(%Sock, SOCK_STATE))) {
    hadd -m %Sock ERROR INTERNAL_ERROR State lost
    _WebSocket.Debug -e %Name $+ >STATE~State lost for %Name
    _WebSocket.RaiseError %Name INTERNAL_ERROR sock state lost
  }
  elseif ($hget(%Sock, SOCK_STATE) == 0 || $v1 == 5) {
    %Error = Connection in closing
  }
  elseif ($v1 !== 4) {
    %Error = WebSocket connection not established
  }
  elseif ($hget(%Sock, CLOSE_PENDING)) {
    %Error = Close frame sent; cannot add more frames
  }
  elseif (%FrameSwitch isincs bt && $0 == 1) {
    %Error = No data to send
  }
  elseif (%DataSwitch !== t && &?* iswm $2 && $0 == 2 && $bvar($2, 0) > 4294967295) {
    %Error = Specified bvar exceeds 4gb
  }
  else {
    if (c isincs %FrameSwitch) {
      %Control = $true
      %Code = 8
      %TypeText = CLOSE
    }
    elseif (p isincs %FrameSwitch) {
      %Control = $true
      %Code = 9
      %TypeText = PING
    }
    elseif (P isincs %FrameSwitch) {
      %Control = $true
      %Code = 10
      %TypeText = PONG
    }
    elseif (b isincs %FrameSwitch) {
      %Code = 2
      %TypeText = BINARY
    }
    bunset &_WebSocket_CompiledFrame &_WebSocket_FrameData &_WebSocket_SendBuffer
    if (t !isin %DataSwitch && &?* iswm $2 && $0 == 2) {
      %BVar = $2
      %BVarUnset = $false
    }
    elseif ($0 == 2) {
      bset -t %BVar 1 $2-
    }
    bset &_WebSocket_CompiledFrame 1 $calc(128 + %Code)
    if ($Bvar(%BVar, 0)) {
      %Size = $v1
      %Index = 1
      if (%Size < 126) {
        bset &_WebSocket_CompiledFrame 2 $calc(128 + $v1)
      }
      elseif ($v1 isnum 126-65535) {
        bset &_WebSocket_CompiledFrame 2 254 $regsubex($base($v1, 10, 2, 16), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }
      else {
        bset &_WebSocket_CompiledFrame 2 255 $regsubex($base($v1, 10, 2, 64), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }
      %MaskByte1 = $r(0, 255)
      %MaskByte2 = $r(0, 255)
      %MaskByte3 = $r(0, 255)
      %MaskByte4 = $r(0, 255)
      bset &_WebSocket_CompiledFrame $calc($bvar(&_WebSocket_CompiledFrame, 0) + 1) %MaskByte1 %MaskByte2 %MaskByte3 %MaskByte4
      while (%Index <= %Size) {
        bset &_WebSocket_CompiledFrame $calc($bvar(&_WebSocket_CompiledFrame, 0) + 1) $xor($bvar(%BVar, %Index), $($+(%, MaskByte, $calc((%Index - 1) % 4 + 1)), 2))
        inc %Index
      }
      if (%BVarUnset) {
        bunset %BVar
      }
    }
    else {
      bset &_WebSocket_CompiledFrame 2 0
    }
    if ($hget(%Sock, WSFRAME_Buffer, &_WebSocket_SendBuffer)) {
      bcopy -c &_WebSocket_SendBuffer $calc($bvar(&_WebSocket_SendBuffer, 0) + 1) &_WebSocket_CompiledFrame 1 -1
      hadd -mb %Sock WSFRAME_Buffer &_WebSocket_SendBuffer
      bunset &_WebSocket_SendBuffer
    }
    else {
      hadd -mb %Sock WSFRAME_Buffer &_WebSocket_CompiledFrame
    }
    bunset &_WebSocket_CompileFrame
    _WebSocket.Debug -i %Name $+ >FRAME_SEND~ $+ %TypeText frame queued.
    if (%Code === 8) {
      hadd -m %Sock CLOSE_PENDING $true
    }
    _WebSocket.Send %Sock
  }
  :error
  if ($error || %Error) {
    echo $color(info).dd -s * /WebSockWrite: $v1
    _WebSocket.Debug -e /WebSockWrite~ $+ $v1
    reseterror
    halt
  }
}
alias -l _WebSocket.Send {
  bunset &_WebSocket_SendBuffer
  var %Name = $gettok($1, 2-, 95), %Error, %Space, %Size
  if (!$sock($1)) {
    %Error = SOCK_ERROR Connection doesn't exist
  }
  elseif (!$hget($1) || !$len($hget($1, SOCK_STATE))) {
    %Error = INTERNAL_ERROR State lost
  }
  elseif ($hget($1, SOCK_STATE) === 3) {
    %Error = INTERNAL_ERROR State doesn't match data sending
  }
  elseif ($v1 === 2) {
    if (!$hget($1, HTTPREQ_HEAD, &_WebSocket_SendBuffer) && !$sock($1).sq) {
      _WebSocket.Debug -i2 %Name $+ >Head_Sent Finished sending request.
      hadd -m $sockname SOCK_STATE 3
      .signal -n WebSocket_REQSENT_ $+ %Name
    }
    elseif ($bvar(&_WebSocket_SendBuffer, 0) && $sock($1).sq < 16384) {
      %Space = $calc($v2 - $v1)
      %Size = $bvar(&_WebSocket_SendBuffer, 0)
      if (%Size <= %Space) {
        sockwrite $1 &_WebSocket_SendBuffer
        hdel $1 HTTPREQ_HEAD
        _WebSocket.Debug -i %Name $+ >REQ_SEND~Entire head now added to send buffer
      }
      else {
        sockwrite -b $1 %Space &_WebSocket_SendBuffer
        bcopy -c &_WebSocket_SendBuffer 1 &_WebSocket_SendBuffer $calc(%Space +1) -1
        hadd -mb $1 HTTPREQ_HEAD &_WebSocket_SendBuffer
        _WebSocket.Debug -i %Name $+ >REQ_SEND~Added %Space bytes of the head to the send buffer
      }
    }
  }
  elseif ($hget($1, WSFRAME_Buffer, &_WebSocket_SendBuffer) && $sock($1).sq < 16384) {
    %Space = $calc($v2 - $v1)
    %Size = $bvar(&_WebSocket_SendBuffer, 0)
    if (%Size <= %Space) {
      sockwrite $1 &_WebSocket_SendBuffer
      hdel $1 WSFRAME_Buffer
      _WebSocket.Debug -i %Name $+ >FRAME_SEND~All pending frame data now in send buffer
    }
    else {
      sockwrite -b $1 %Space &_WebSocket_SendBuffer
      bcopy -c &_WebSocket_SendBuffer 1 &_WebSocket_SendBuffer $calc(%Space +1) -1
      hadd -mb $1 WSFRAME_Buffer &_WebSocket_SendBuffer
      _WebSocket.Debug -i %Name $+ >FRAME_SEND~Added %Space bytes of frame data to send buffer
    }
  }
  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror
    _WebSocket.Debug -e %Name $+ >FRAME_SEND %Error
    _WebSocket.RaiseError %Name %Error
  }
}
on $*:SOCKWRITE:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %State = $hget($sockname, SOCK_STATE)
  if ($sockerr) {
    %Error = SOCK_ERROR Failed to write to connection
  }
  elseif (!$hget($sockname) || !$len(%State)) {
    %Error = INTERNAL_ERROR State lost
  }
  elseif (%State !== 2 && %State !== 4 && %State !== 5) {
    %Error = INTERNAL_ERROR State doesn't corrospond with data-send attempt: %State
  }
  else {
    _WebSocket.Send $sockname
  }
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    _WebSocket.debug -e %Name $+ >SOCKWRITE~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}

alias mWebSockVer {
  return 01000.0002
}