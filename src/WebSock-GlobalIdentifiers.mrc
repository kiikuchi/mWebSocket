;; Returns various information about a WebSock
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