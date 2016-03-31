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
  if ($isid || $event !== signal || !$regex($signal, /^WebSocket_INIT_(?!\d+$)([^?*-][^?*]*)$/i)) {
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
        hadd -m %Sock $+(HTTPREQ_HEADER, %Index, _, %Header) $2-
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

;; /WebSockWrite -[c|p|P|b|t]+wt name [data]
alias WebSockWrite {
  if ($isid) {
    return
  }

  var %FrameSwitch, %DataSwitch, %Name, %Sock, %Error, %CompFrame = &_WebSocket_CompiledFrame, %Type, %Data, %BUnset, %Size, %Index = 1, %Mask1, %Mask2, %Mask3, %Mask4, %QuadMask

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

  ;; validate switches and parameters
  if ($regex(%FrameSwitch, ([^cpPbt]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?\1)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?([cpPbt]))) {
    %Error = Conflicting switches: $regml(1) $regml(2)
  }
  elseif ($regex(%DataSwitch, ([^tw]))) {
    %Error = Invalid Data-force switch + $+ $regml(1)
  }

  ;; Validate parameter
  elseif ($0 < 1) {
    %Error = Missing parameters
  }
  elseif (t !isincs %DataSwitch && $0 == 2 && &?* iswm $2 && $bvar($2, 0) > 4294967295) {
    %Error = Specified bvar exceeds 4gb
  }
  else {

    ;;-------------------;;
    ;;    BUILD FRAME    ;;
    ;;-------------------;;

    ;; Cleanup just to be safe
    bunset &_WebSocket_SendBuffer &_WebSocket_FrameData %CompFrame

    ;; Frame type deduction in the order of:
    ;;   PONG, PING, CLOSE, BINARY, TEXT
    if (P isincs %FrameSwitch) {
      bset %CompFrame 1 138
      %Type = PONG
    }
    elseif (p isincs %FrameSwitch) {
      bset %CompFrame 1 137
      %Type = PING
    }
    elseif (c isincs %FrameSwitch) {
      bset %CompFrame 1 136
      %Type = CLOSE
    }
    elseif (b isincs %FrameSwitch) {
      bset %CompFrame 1 130
      %Type = BINARY
    }
    else {
      bset %CompFrame 1 129
      %Type = TEXT
    }

    ;; If the data parameter is a bvar use it, otherwise use an internal
    ;; bvar and, if there is data, store that data in the bvar
    if (t !isincs %DataSwitch && &?* iswm $2 && $0 == 2) {
      %Data = $2
    }
    else {
      %Data = &_WebSocket_FrameData
      if ($0 > 1) {
        bset -tc %Data 1 $2-
      }
    }

    ;; if there's data to accompany the frame
    if ($bvar(%Data, 0)) {
      %Size  = $v1

      ;; if a control frame is being sent and its data is larger than 125
      ;; bytes
      if (%Type !isincs TEXT BINARY && %Size > 125) {
        %Error = Control frame data cannot be larger than 125 bytes
        goto error
      }

      ;; payload is larger than what mIRC can safely handle
      elseif (%Size > 4294967295) {
        %Error = Frame data exceeds 4gb limit
        goto error
      }

      ;; Payload size requires a 64bit integer
      elseif (%Size > 65535) {
        bset %CompFrame 2 255 0 0 0 0 $replace($longip(%Size), ., $chr(32))
      }

      ;; Payload size requires a 16bit integer
      elseif (%Size > 125) {
        bset %CompFrame 2 254 $replace($gettok($longip(%Size), 3-, 46), ., $chr(32))
      }

      ;; Payload size can fit within a 7bit integer
      else {
        bset %CompFrame 2 $calc(128 + %Size)
      }

      ;; Create masking octlets at random and append them to the frame
      %Mask1 = $r(0, 255)
      %Mask2 = $r(0, 255)
      %Mask3 = $r(0, 255)
      %Mask4 = $r(0, 255)
      bset %CompFrame $calc($bvar(%CompFrame, 0) + 1) %Mask1 %Mask2 %Mask3 %Mask4

      ;; Mask 4 octlets at a time so long as there is atleast 4 octlets to mask
      %QuadMask = $calc(%Size - (%Size % 4))
      while (%Index < %QuadMask) {
        bset %CompFrame $calc($bvar(%CompFrame,0) +1) $xor($bvar(%Data,%Index),%Mask1) $xor($bvar(%Data,$calc(1+ %Index)),%Mask2) $xor($bvar(%Data,$calc(2+ %Index)),%Mask3) $xor($bvar(%Data,$calc(3+ %Index)),%Mask4)
        inc %Index 4
      }

      ;; Mask any remaining octlets
      if (%Index <= %Size) {
        bset %CompFrame $calc($bvar(%CompFrame,0) +1) $xor($bvar(%Data,%Index),%Mask1)
        inc %index
        if (%Index <= %Size) {
          bset %CompFrame $calc($bvar(%CompFrame,0) +1) $xor($bvar(%Data,%Index),%Mask2)
          inc %index
          if (%Index <= %Size) {
            bset %CompFrame $calc($bvar(%CompFrame,0) +1) $xor($bvar(%Data,%Index),%Mask3)
          }
        }
      }
    }

    ;; if no data to accompany the frame set the PayLoad-Length byte to 0
    else {
      bset %CompFrame 2 0
    }

    ;;----------------------------------;;
    ;;    Wildcard WebSock Specified    ;;
    ;;----------------------------------;;
    if (w isincs %Switches) {

      ;; loop over all matching websock handles
      while ($sock(_WebSocket_ $+ $1, %Index)) {
        %Sock = $v1

        ;; Check to make sure the WebSock is ready to send data
        if ($hget(%Sock, SOCK_STATE) == 4 && !$hget(%Sock, CLOSE_PENDING)) {

          ;; Add the frame to the send buffer
          if ($hget(%Sock, WSFRAME_Buffer, &_WebSocket_SendBuffer)) {
            bcopy -c &_WebSocket_SendBuffer $calc($bvar(&_WebSocket_SendBuffer, 0) + 1) %CompFrame 1 -1
            hadd -b %Sock WSFRAME_Buffer &_WebSocket_SendBuffer
          }
          else {
            hadd -b %Sock WSFRAME_Buffer %CompFrame
          }

          ;; Update state if a CLOSE frame is being sent, output debug message,
          ;; cleanup, and process the send queue
          if (%Type == CLOSE) {
            hadd %Sock CLOSE_PENDING $true
          }
          _WebSocket.Debug -i %Name $+ >FRAME_SEND~ $+ %Type frame queued. Size: $bvar(%CompFrame, 0) -- Head: $bvar(%CompFrame, 1, 2) -- Payload-Len: $calc($bvar(%CompFrame, 2) % 128)
          bunset &_WebSocket_SendBuffer &_WebSocket_FrameData
          _WebSocket.Send %Sock
        }
        inc %Index
      }

      ;; Cleanup the compiled frame
      bunset %CompFrame
    }

    ;;---------------------------------;;
    ;;    Literel WebSock Specified    ;;
    ;;---------------------------------;;
    ;; Validate Name and socket state
    elseif (!$regex($1, ^(?!\d+$)[^?*]+$) || !$sock(_WebSocket_ $+ $1)) {
      %Error = WebSocket does not exist
    }
    elseif (!$hget(_WebSocket_ $+ $1) || !$len($hget(_WebSocket_ $+ $1, SOCK_STATE))) {
      hadd -m _WebSocket_ $+ $1 ERROR INTERNAL_ERROR State lost
      _WebSocket.Debug -e $1 $+ >STATE~State lost for $1
      _WebSocket.RaiseError $1 INTERNAL_ERROR sock state lost
    }
    elseif ($hget(_WebSocket_ $+ $1, CLOSE_PENDING)) {
      %Error = Close frame already queued; Cannot queue more
    }
    elseif ($hget(_WebSocket_ $+ $1, SOCK_STATE) isin 0 5) {
      %Error = Connection in closing
    }
    elseif ($hget(_WebSocket_ $+ $1, SOCK_STATE) !== 4) {
      %Error = WebSocket connection not established
    }

    ;; Add the frame to the send queue
    else {
      %Name = $1
      %Sock = _WebSocket_ $+ $1

      ;; Add the frame to the send buffer
      if ($hget(%Sock, WSFRAME_Buffer, &_WebSocket_SendBuffer)) {
        bcopy -c &_WebSocket_SendBuffer $calc($bvar(&_WebSocket_SendBuffer, 0) + 1) %CompFrame 1 -1
        hadd -b %Sock WSFRAME_Buffer &_WebSocket_SendBuffer
      }
      else {
        hadd -b %Sock WSFRAME_Buffer %CompFrame
      }

      ;; Update state if a CLOSE frame is being sent, output debug message,
      ;; cleanup, and process the send queue
      if (%Type == CLOSE) {
        hadd %Sock CLOSE_PENDING $true
      }
      _WebSocket.Debug -i %Name $+ >FRAME_SEND~ $+ %Type frame queued. Size: $bvar(%CompFrame, 0) -- Head: $bvar(%CompFrame, 1, 2) -- Payload-Len: $calc($bvar(%CompFrame, 2) % 128)
      bunset &_WebSocket_SendBuffer %CompFrame &_WebSocket_FrameData
      _WebSocket.Send %Sock
    }
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

;; /WebSockClose -wfe<code> sockname [reason]
alias WebSockClose {
  var %Switches, %Error, %Name, %Sock, %StatusCode, %Index

  ;; Get switches, websock name, and sockname from inputs
  if (-* iswm $1) {
    %Switches = $mid($1, 2)
    tokenize 32 $2-
  }

  ;; Validate switches
  if ($regex(%Switches, ([^wfe\d]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /([wfe]).*\1/)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%switches, /([fe]).*?([fe])/)) {
    %Error = Conflicting switches specified: $regml(1) $regml(2)
  }
  elseif (e isincs %Switches && !$regex(StatusCode, %Switches, /e(\d{4})/)) {
    %Error = Invalid error code
  }
  elseif (e !isincs %Switches && $regex(%Switches, \d)) {
    %Error = Status Codes can only be specified with the -e switch
  }

  ;; Validate parameters
  elseif ($0 < 1) {
    %Error = Missing parameters
  }

  else {

    ;; if the connection is not to be force-closed
    ;; build a close message
    if (f !isincs %Switches) {

      ;; A status code was specified, convert to 16bit int
      if ($regml(StatusCode, 0)) {
        %StatusCode = $base($regml(StatusCode), 10, 2, 16)
      }
      else {
        %StatusCode = 1000
      }
      bset -c &_WebSocket_SendCloseMsg 1 $base($left(%StatusCode, 8), 2, 10) $base($mid(%StatusCode, 9), 2, 10)

      ;; If a message is to accompany the status code, append it
      if ($0 > 1) {
        bset -t &_WebSocket_SendCloseMsg 3 $2-
      }
    }

    ;; If w is not in the switches, the sockname is literal
    if (w !isincs %Switches) {

      %Name = $1
      %Sock = _WebSocket_ $+ %Name

      if (!$regex(%Name, /^(?!\d+$)[^?*-][^?*]*$/)) {
        %Error = Invalid websocket name
      }

      ;; Validate state
      elseif (!$sock(%Sock)) {
        ._WebSocket.Cleanup %Sock
        %Error = WebSocket does not exist
      }

      ;; if its a force close or the HTTP handshake is incomplete cleanup the
      ;; connection
      elseif (f isincs %Switches || $hget(%Sock, SOCK_STATE) isnum 1-3) {
        _WebSocket.Cleanup %Sock
      }

      ;; check state
      elseif ($hget(%Sock, SOCK_STATE) == 0 || $v1 == 5) {
        %Error = Connection already closing
      }
      elseif ($hget(%Sock, CLOSE_PENDING)) {
        %Error = CLOSE frame already sent
      }
      else {
        WebSockWrite -c %Name &_WebSocket_SendCloseMsg
        bunset &_WebSocket_SendCloseMsg
      }
    }
    else {
      %Index = 1
      while ($sock(_WebSocket_ $+ $1, %Index)) {

        ;; grab the sock name
        %Sock = $v1

        ;; if the f switch is specified or the http handshake has not completed
        ;; simply close the websock and move on to the next sock in the list
        if (f isincs %Switches || $hget(%Sock, SOCK_STATE) isnum 1-3) {
          _WebSocket.Cleanup %Sock
          continue
        }

        ;; otherwise, check if the websock is in the 'ready' state and does not have
        ;; a close pending. If so, send a close frame
        elseif ($hget(%Sock, SOCK_STATE) == 4 && !$hget(%Sock, CLOSE_PENDING)) {
          WebSockWrite -c $gettok(%Sock, 2-, 95) &_WebSocket_SendCloseMsg
        }

        ;; move to the next socket in the list
        inc %Index
      }
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

;; /WebSockList
;;   Lists all open websocket handlers by name
alias WebSockList {
  var %Index = 1, %Count = $sock(_WebSocket_?*, 0)
  if (!%Count) {
    echo $color(info).dd -age * No open WebSockets
  }
  else {
    echo $color(info).dd -ag -
    echo $color(info).dd -ag * Open WebSockets:
    while (%Index <= %Count) {
      echo -ag * $gettok($sock(_WebSocket_?*, %Index), 2-, 95)
      inc %Index
    }
    echo $color(info).dd -ag -
  }
}