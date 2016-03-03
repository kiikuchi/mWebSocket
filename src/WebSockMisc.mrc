alias WebSock {
  if (!$isid) {
    return
  }

  var %Name, %Sock, %State, %Find, %Index, %Header

  ;; Deduce the name to use
  if (!$0) {
    if ($event !== signal && !$regex($signal, ^WebSocket_[A-Z]+_(?!-)(?!\d*$)(.*)$)) {
      return
    }
    %Name = $regml(1)
  }
  elseif ($regex(name, $1, ^(?!-)(?!\d*$)(.*)$)) {
    %Name = $regml(name, 1)
  }
  else {
    return
  }

  %Sock = WebSocket_ $+ %Name

  ;; no matching socket and hashtable?
  if (!$sock(%Sock) && !$hget(%sock)) {
    return
  }

  ;; no prop? return name
  if (!$prop) {
    return %Name
  }

  ;; $WebSock().State
  elseif ($prop == State) {
    return $hget(%Sock, SOCK_STATE)
  }

  ;; $WebSock().StateText
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
      return SENDING_REQUEST
    }
    elseif (%State == 3) {
      return RESPONSE_PENDING
    }
    elseif (%State == 4) {
      return READY
    }
    elseif (%State == 5) {
      return WEBSOCKET_CLOSING
    }
  }

  ;; $WebSock().Ssl
  elseif ($prop == Ssl) {
    return $iif($sock(%Sock), $sock(%sock).ssl, $hget(%Sock, SOCK_SSL))
  }

  ;; $WebSock().Host
  elseif ($prop == Host) {
    return $iif($sock(%Sock).addr, $v1, $hget(%Sock, SOCK_ADDR))
  }

  ;; $WebSock().Port
  elseif ($prop == Port) {
    return $iif($sock(%Sock).port, $v1, $hget(%Sock, SOCK_PORT))
  }

  ;; $WebSock().Uri
  elseif ($prop == Uri) {
    return $hget(%Sock, SOCK_URI))
  }

  ;; $WebSock().HttpVersion
  elseif ($prop == HttpVersion) {
    return $hget(%Sock, HTTPRESP_HttpVersion)
  }

  ;; $WebSock().HttpStatus
  elseif ($prop == HttpStatus) {
    return $hget(%Sock, HTTPRESP_StatusCode)
  }

  ;; $WebSock().HttpStatusText
  elseif ($prop == HttpStatusText) {
    return $hget(%Sock, HTTPRESP_StatusText)
  }

  ;; $WebSock().Headers
  elseif ($prop == Headers) {
    return $hfind(%Sock, ^HTTPRESP_HEADER\d+_, 0, r)
  }

  ;; $WebSock().HttpHeader
  elseif ($prop == HttpHeader) {
    if (!$hget(%Sock) || $0 < 2 || ($0 == 3 && ($3 !isnum 0- || . isin $3)) || $0 > 3) {
      return
    }

    ;; $WebSock(name, header[, n]).HttpHeader
    elseif ($0 == 3 || $2 !isnum 0- || . isin $2) {
      %Header = $hfind(%Sock, ^HTTPRESP_HEADER\d+_\Q $+ $replacecs($2, \E, \Q\\E\E) $+ \E$, $iif($0 == 3, $v1, 1), r)
      if (!%index) {
        return %Header
      }
      return $hget(%Sock, %Header)
    }

    ;; $WebSock(name, n).HttpHeader
    elseif ($2) {
      return $gettok($hfind(%Sock, ^HTTPRESP_HEADER $+ $2 $+ _, 1, r), 3-, 95)
    }
    else {
      return $hfind(%Sock, ^HTTPRESP_HEADER\d+_, 0, r)
    }
  }
}

;; /WebSockHeader Header Value
alias WebSockHeader {
  var %Error, %Name, %Sock
  if ($isid || $event !== signal || !$regex(name, $signal, ^WebSocket_INIT_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  else {
    %Name = $regml(name, 1)
    %Sock = WebSocket_ $+ %Name

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

;; $WebSockType
;;   Returns the frame type
alias WebSockType {
  if ($isid || $event !== signal || !$regex(event, $signal, ^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  return $hget(WebSocket_ $+ $regml(event, 1), WSFRAME_TYPE)
}

;; $WebSockText
;;   Returns the frame data as utf8 text
alias WebSockText {
  if ($isid || $event !== signal || !$regex(event, $signal, ^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  bunset &_WebSockFrameData
  if ($hget(WebSocket_ $+ $regml(event, 1), WSFRAME_DATA, &_WebSockFrameData)) {
    return $bvar(&_WebSockFrameData, 1, 4000).text
  }
}

;; $WebSockData(&bvar)
;;   fills the specified bvar with the frame data
alias WebSockData {
  if ($isid || $event !== signal || !$regex(event, $signal, ^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  elseif ($0 == 1 && &?* !iswm $1 && $chr(32) isin $1) {
    if ($bvar($1, 0)) {
      bunset $1
    }
    return $hget(WebSocket_ $+ $regml(event, 1)m WSFRAME_DATA, $1)
  }
}

;; $WebSockErr
;;   Returns the error that caused the error event to be raised
alias WebSockErr {
  if ($isid || $event !== signal || !$regex(event, $signal, ^WebSocket_ERROR_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  return $gettok($hget(WebSocket_ $+ $regml(event, 1), ERROR), 1, 32)
}

;; $WebSockErrMsg
;;   Returns the error msg that caused the error event to be raised
alias WebSockErrMsg {
  if ($isid || $event !== signal || !$regex(event, $signal, ^WebSocket_ERROR_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  return $gettok($hget(WebSocket_ $+ $regml(event, 1), ERROR), 2-, 32)
}

;; /WebSockDebug [on|off]
;; $WebSockDebug
alias WebSockDebug {

  ;; If identifier, return the debug state
  if ($isid) {
    return $iif($group(#WebSocket_Debug) == on, $true, $false)
  }

  ;; Toggle debug group according to input
  if ($1 == on || $1 == enable) {
    .enable #WebSocket_Debug
  }
  elseif ($1 == off || $1 == disable) {
    .disable #WebSocket_Debug
  }
  elseif (!$0) {
    $iif($group(#WebSocket_Debug) == on, .disable, .enable) #WebSocket_Debug
  }
  else {
    echo -gs * /WebSockDebug: Invalid input
    halt
  }

  ;; create debug window if required
  if ($group(#WebSocket_Debug) == on && !$window(@WebSocketDebug)) {
    window -nzk0 @WebSocketDebug
  }
}

;; /_WebSocket.BAdd &bvar text
;; adds the specified text to the end of the bvar
alias -l _WebSocket.BAdd {
  bset -t $1 $calc($bvar($1, 0) + 1) $2- $+ $crlf
}

;; if the group is on the contained alias is used for outputting debug messages:
;; /_WebSocket.Debug -ewiNs [title~][msg]
#WebSocket_Debug on
alias -l _WebSocket.Debug {

  ;; if the debug window isn't open, disable debugging
  if (!$window(@WebSocketDebug)) {
    .disable #WebSocket_Debug
  }
  else {

    ;; process head color
    var %Color = 12, %Title = WebSocket, %Msg
    if (-* iswm $1) {
      if ($1 == -e)  %Color = 04
      if ($1 == -w)  %Color = 07
      if ($1 == -i)  %Color = 03
      if ($1 == -i2) %Color = 10
      if ($1 == -s)  %Color = 12
      tokenize 32 $2-
    }

    ;; seperate title and message
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

    ;; output debug msg to window
    aline @WebSocketDebug $+($chr(3), %Color, [, %Title, ], $chr(15)) %msg
  }
}
#WebSocket_Debug end

;; if the group is off this alias is used for outputting debug messages which do nothing:
alias -l _WebSocket.Debug

;; menu for the debug window
menu @WebSocketDebug {
  $iif($WebSockDebug, Disable, Enable): WebSocketDebug
  -
  Save: noop
  Clear:clear @WebSocketDebug
  -
  Close: .disable #WebSocket_Debug | close -@ @WebSocketDebug
}

;; if the debug window gets closed, disable debugging
on *:CLOSE:@WebSocketDebug:{
  .disable #WebSocket_Debug
}

on *:UNLOAD:{
  sockclose WebSocket_*
  hfree -w WebSocket_
  .timerWebSocket_TimeOut_* off
}