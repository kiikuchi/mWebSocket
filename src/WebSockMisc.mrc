;; /_WebSocket.BAdd &bvar text
;; adds the specified text to the end of the bvar
alias -l _WebSocket.BAdd {
  bset -t $1 $calc($bvar($1, 0) + 1) $2- $+ $crlf
}

;; /_WebSocket.RaiseError name err_type err_msg
;;   Raises an error event then cleans up the websocket
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

  ;; Deduce the websock and socket name
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
    return $hget(%Sock, HTTPREQ_URI))
  }

  ;; $WebSock().HttpVersion
  elseif ($prop == HttpVersion) {
    return $hget(%Sock, HTTPRESP_HttpVersion)
  }

  ;; $WebSock().HttpStatus
  elseif ($prop == StatusCode) {
    return $hget(%Sock, HTTPRESP_StatusCode)
  }

  ;; $WebSock().HttpStatusText
  elseif ($prop == StatusText) {
    return $hget(%Sock, HTTPRESP_StatusText)
  }

  ;; $WebSock().HttpHeader
  elseif ($prop == HttpHeader) {
    ;; validate inputs
    if (!$hget(%Sock) || $0 < 2 || !$len($2) || $0 > 3 || ($0 == 3 && (!$len($3) || $3 !isnum 0- || . isin $3))) {
      return
    }

    ;; $WebSock(Name, n).HttpHeader
    elseif ($0 == 2 && . !isin $2) {
      if (!$2) {
        return $hfind(%Sock, /^HTTPRESP_HEADER\d+_/, 0, r)
      }
      return $gettok($hfind(%Sock, ^HTTPRESP_HEADER $+ $2 $+ _, 1, r), 3-, 95)
    }

    ;; $WebSock(Name, header, n).Httpheader
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

;; /WebSockHeader Header Value
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

;; $WebSockType
;;   Returns the frame type
alias WebSockType {

  ;; Validate the alias was used from a WebSocket frame signal event
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/i)) {
    return
  }

  ;; Return the stored frame type
  return $hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_TYPE)
}

;; $WebSockTypeText
;;   Returns the text equivialnt of the frame type
alias WebSockTypeText {

  ;; Validate the alias was used from a WebSocket frame signal event
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/i)) {
    return
  }

  ;; Get the stored frame type
  var %type = $hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_TYPE)

  ;; Return the type as text:
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

;; $WebSockText
;;   Returns the frame data as utf8 text
alias WebSockText {

  ;; Validate the alias was used from a WebSocket frame signal event
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_(?:DATA|PING|PONG|CLOSING)_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }

  ;; clear the bvar we need to read data into
  bunset &_WebSocket_EventFrameData

  ;; retrieve the frame data
  if ($hget(_WebSocket_ $+ $regml(event, 1), WSFRAME_DATA, &_WebSocket_EventFrameData)) {

    ;; return the first 3500 bytes
    return $bvar(&_WebSocket_EventFrameData, 1, 3500).text
  }
}

;; $WebSockData(&bvar)
;;   fills the specified bvar with the frame data
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

;; $WebSockErr
;;   Returns the error that caused the error event to be raised
alias WebSockErr {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_ERROR_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  return $gettok($hget(_WebSocket_ $+ $regml(event, 1), ERROR), 1, 32)
}

;; $WebSockErrMsg
;;   Returns the error msg that caused the error event to be raised
alias WebSockErrMsg {
  if (!$isid || $event !== signal || !$regex(event, $signal, /^WebSocket_ERROR_(?!\d*$)([^?*-][^?*-]*)$/)) {
    return
  }
  return $gettok($hget(_WebSocket_ $+ $regml(event, 1), ERROR), 2-, 32)
}

;; /WebSockDebug [on|off]
;; $WebSockDebug
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

;; if the group is "on" the contained alias is used for outputting debug messages:
;; /_WebSocket.Debug -ewiNs [title~][msg]
#_WebSocket_Debug off
alias -l _WebSocket.Debug {

  ;; if the debug window isn't open, disable debugging
  if (!$window(@WebSocketDebug)) {
    .disable #_WebSocket_Debug
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
#_WebSocket_Debug end

;; if the group is off this alias is used for outputting debug messages which do nothing:
alias -l _WebSocket.Debug

;; menu for the debug window
menu @WebSocketDebug {
  $iif($WebSockDebug, Disable, Enable): WebSocketDebug
  -
  Save: noop
  Clear:clear @WebSocketDebug
  -
  Close: .disable #_WebSocket_Debug | close -@ @WebSocketDebug
}

;; if the debug window gets closed, disable debugging
on *:CLOSE:@WebSocketDebug:{
  .disable #_WebSocket_Debug
}

on *:START:{
  if ($WebSockDebug) {
    window -nzk0 @WebSocketDebug
  }
}

;; If the script gets unloaded, cleanup open WebSocket instances
on *:UNLOAD:{
  sockclose _WebSocket_*
  hfree -w _WebSocket_
  .timer_WebSocket_Timeout_* off
  if ($Window(@WebSocketDebug)) {
    close -@ @WebSocketDebug
  }
}