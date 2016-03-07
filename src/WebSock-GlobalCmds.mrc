;; /WebSockOpen name uri [timeout]
alias WebSockOpen {
  if ($isid) {
    return
  }

  var %Error, %Sock, %Host, %Ssl, %Port

  ;; Validate inputs
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

    ;; Cleanup after a non-existant socket just to be safe
    if ($hget(%Sock)) {
      ._WebSocket.Cleanup %Sock
    }

    ;; SSL determination
    if (wss:// == $regml(uri, 1)) {
      %Ssl = $true
    }
    else {
      %Ssl = $false
    }

    ;; Port determination
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

    ;; Store state variables
    hadd -m %Sock SOCK_STATE 1
    hadd %Sock SOCK_SSL %Ssl
    hadd %Sock SOCK_ADDR %Host
    hadd %Sock SOCK_PORT %Port
    hadd %Sock HTTPREQ_URI $2
    hadd %Sock HTTPREQ_RES $iif($len($regml(uri, 4)), $regml(uri, 4), /)
    hadd %Sock HTTPREQ_HOST %Host $+ $iif((%Ssl && %Port !== 443) || (!%Ssl && %Port !== 80), : $+ %Port)

    ;; Start timeout timer
    $+(.timer, _WebSocket_Timeout_, $1) -oi 1 $iif($3, $v1, 300) _WebSocket.ConnectTimeout %Name

    ;; Begin socket connection and output debug message
    sockopen $iif(%ssl, -e) %sock %host %port
    _WebSocket.Debug -i Connecting> $+ $1 $+ ~Connecting to %host $iif(%ssl, with an SSL connection) on port %port as %sock
  }

  ;; Handle errors
  :error
  if ($error || %error) {
    echo $color(info).dd -s * /WebSockOpen: $v1
    _WebSocket.Debug -e /WebSockOpen~ $+ $v1
    reseterror
    halt
  }
}

;; /WebSockHeader Header Value
;;   Settings the HTTP header for a pending WebSock http request
alias WebSockHeader {
  var %Error, %Name, %Sock

  ;; Validate the alias was used from a WebSocket INIT signal event
  if (!$isid || $event !== signal || !$regex($signal, /^WebSocket_INIT_(?!\d+$)([^?*-][^?*]*)$/i)) {
    return
  }
  else {
    %Name = $regml(name, 1)
    %Sock = _WebSocket_ $+ %Name

    ;; validate state
    if (!$sock(%Sock)) {
      %Error = WebSocket not in use
    }

    ;; validate inputs
    elseif ($0 !== 2) {
      %Error = Missing parameters
    }

    ;; Store the header as HTTPREQ_HEADERn_NAME VALUE
    ;;   where n is the number of stored headers + 1
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

  ;; Handler errors
  :error
  if ($error || %Error) {
    echo -sg * /WebSockHeader: $v1
    reseterror
    halt
  }
}

;; /WebSockWrite -[c|p|P|b|t]+t name [data]
alias WebSockWrite {
  if ($isid) {
    return
  }

  var %FrameSwitch, %DataSwitch, %Name, %Sock, %Error, %Control = $false, %Code = 1, %TypeText = TEXT, %BVar = &_WebSocket_FrameData, %BVarUnset = $true, %Index, %Size, %MaskByte1, %MaskByte2, %MaskByte3, %MaskByte4

  ;; parse switches
  if ($left($1, 1) isin +-) {
    noop $regex($1, /^((?:-[^+]*)?)((?:\+.*)?)$/))
    %FrameSwitch = $mid($regml(1), 2)
    %DataSwitch = $mid($regml(2), 2)
    tokenize 32 $2-
  }

  ;; deduce websocket and socket names
  %Name = $1
  %Sock = _WebSocket_ $+ $1

  ;; validate switches
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

  ;; validate name parameter
  elseif (!$regex($1, ^(?!\d+$)[^?*]+$) || !$sock(%Sock)) {
    %Error = WebSocket does not exist
  }

  ;; validate socket state
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

  ;; Validate data
  elseif (%FrameSwitch isincs bt && $0 == 1) {
    %Error = No data to send
  }
  elseif (%DataSwitch !== t && &?* iswm $2 && $0 == 2 && $bvar($2, 0) > 4294967295) {
    %Error = Specified bvar exceeds 4gb
  }
  else {

    ;; Frame-Type delegation
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

    ;; Store data in bvar if need be
    bunset &_WebSocket_CompiledFrame &_WebSocket_FrameData &_WebSocket_SendBuffer

    if (t !isin %DataSwitch && &?* iswm $2 && $0 == 2) {
      %BVar = $2
      %BVarUnset = $false
    }
    elseif ($0 >= 2) {
      bset -t %BVar 1 $2-
    }

    ;; store code: 1000 xxxx
    bset &_WebSocket_CompiledFrame 1 $calc(128 + %Code)

    ;; If there is data to accompany the frame
    if ($Bvar(%BVar, 0)) {
      %Size = $v1
      %Index = 1

      ;; build payload-size field
      if (%Size < 126) {
        bset &_WebSocket_CompiledFrame 2 $calc(128 + $v1)
      }
      elseif ($v1 isnum 126-65535) {
        bset &_WebSocket_CompiledFrame 2 254 $regsubex($base($v1, 10, 2, 16), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }
      else {
        bset &_WebSocket_CompiledFrame 2 255 $regsubex($base($v1, 10, 2, 64), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }

      ;; create masking bytes at random and append them to the frame
      %MaskByte1 = $r(0, 255)
      %MaskByte2 = $r(0, 255)
      %MaskByte3 = $r(0, 255)
      %MaskByte4 = $r(0, 255)
      bset &_WebSocket_CompiledFrame $calc($bvar(&_WebSocket_CompiledFrame, 0) + 1) %MaskByte1 %MaskByte2 %MaskByte3 %MaskByte4

      ;; loop over each byte of the frame's assocated data
      while (%Index <= %Size) {

        ;; mask the byte and append it to the frame
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

    ;; Add the frame to the send buffer, update state, and begin sending
    if ($hget(%Sock, WSFRAME_Buffer, &_WebSocket_SendBuffer)) {
      bcopy -c &_WebSocket_SendBuffer $calc($bvar(&_WebSocket_SendBuffer, 0) + 1) &_WebSocket_CompiledFrame 1 -1
      hadd -mb %Sock WSFRAME_Buffer &_WebSocket_SendBuffer
      bunset &_WebSocket_SendBuffer
    }
    else {
      hadd -mb %Sock WSFRAME_Buffer &_WebSocket_CompiledFrame
    }
    bunset &_WebSocket_CompileFrame

    ;; Output debug message, update state if a CLOSE frame is being sent, and process the send queue
    _WebSocket.Debug -i %Name $+ >FRAME_SEND~ $+ %TypeText frame queued.
    if (%Code === 8) {
      hadd -m %Sock CLOSE_PENDING $true
    }
    _WebSocket.Send %Sock
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    echo $color(info).dd -s * /WebSockWrite: $v1
    _WebSocket.Debug -e /WebSockWrite~ $+ $v1
    reseterror
    halt
  }
}

;; /WebSockClose -fe<code> sockname [reason]
alias WebSockClose {
  var %Switches, %Error, %Name, %Sock, %errorcode

  ;; Get switches, websock name, and sockname from inputs
  if (-* iswm $1) {
    %Switches = $mid($1, 2)
    tokenize 32 $2-
  }
  %Name = $1
  %Sock = _WebSocket_ $+ %Name

  ;; Validate switches
  if ($regex(%Switches, ([^fe\d]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /([fe]).*\1/)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%switches, /([fe]).*?([fe])/)) {
    %Error = Conflicting switches specified: $regml(1) $regml(2)
  }
  elseif (e isincs %Switches && !$regex(errorcode, %Switches, /e(\d{4})/)) {
    %Error = Invalid error code
  }
  
  ;; Validate parameters
  elseif ($0 < 1) {
    %Error = Missing parameters
  }
  elseif (!$regex(%Name, /^(?!\d+$)[^?*-][^?*]*$/)) {
    %Error = Invalid websocket name
  }
  
  ;; Validate state
  elseif (!$sock(%Sock)) {
    ._WebSocket.Cleanup %Sock
    %Error = WebSocket does not exist
  }

  ;; if its a force close by cleaning up the sock
  elseif (f isincs %Switches) {
    ._WebSocket.Cleanup %Sock
  }

  ;; if the handshake is incomplete, cleanup the sock
  elseif ($hget(%Sock, SOCK_STATE) isnum 1-3) {
    _WebSocket.Cleanup %Sock
  }

  ;; check state
  elseif ($hget(%Sock, SOCK_STATE) == 0 || $v1 == 5) {
    %Error = Connection already closing
  }
  elseif ($hget(%Sock, CLOSE_PENDING)) {
    %Error = CLOSE frame already sent
  }

  ;; send close-frame
  else {
    
    if ($0 == 1) {
      WebSockWrite -c %Name
    }
    else {
      ;; Specified status code, convert to 16bit int
      if ($regml(errorcode, 1)) {
        %StatusCode = $base($v1, 10, 2, 16)
        bset -c &_WebSocket_CloseStatusCode 1 $base($left(%StatusCode, 8), 2, 10) $base($mid(%StatusCode, 9), 2, 10)
      }
      
      ;; No status code, use 1000
      else {
        bset -c &_WebSocket_CloseStatusCode 1 3 232
      }
      
      ;; If a message is to accompany the status code, append it
      if ($0 > 1) {
        bset -t &_WebSocket_CloseStatusCode 2 $2-
      }
      
      ;; call the WebSockWrite command then cleanup
      WebSockWrite -c %Name &_WebSocket_CloseStatusCode
      bunset &_WebSOcket_CloseStatusCode
    }
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    echo $color(info) -sg * /WebSockClose: $v1
    reseterror
    halt
  }
}


;; /WebSockDebug [on|off]
;;   Toggles the WebSock debugger
;;
;; $WebSockDebug
;;   Returns the WebSock debugger state
alias WebSockDebug {

  ;; If identifier, return the debug state
  if ($isid) {
    return $iif($group(#_WebSocket_Debug) == on, $true, $false)
  }

  ;; Toggle debug group according to input
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

  ;; create debug window if required
  if ($group(#_WebSocket_Debug) == on && !$window(@WebSocketDebug)) {
    window -nzk0 @WebSocketDebug
  }
}