

;; /_WebSocket.ConnectTimeout name
;; closes a connection that took too long to establish
alias -l _WebSocket.ConnectTimeout {
  if ($isid) {
    return
  }

  ;; output debug message, raise error event, cleanup
  _WebSocket.Debug -e $1 $+ >TIMEOUT Connection timed out
  _WebSocket.RaiseError $1 SOCK_ERROR Connection timout
}

;; /_WebSocket.Send name
;;   Attempts to move data from the hashtable write buffer to
;;   mIRC's internal sockwrite buffer
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

  ;; HTTP Request send handling
  elseif ($v1 === 2) {

    ;; if the buffer and send queue is empty, the request has finished being sent
    ;; output debug message, update state, and raise REQSENT event
    if (!$hget($1, HTTPREQ_HEAD, &_WebSocket_SendBuffer) && !$sock($1).sq) {
      _WebSocket.Debug -i2 %Name $+ >Head_Sent Finished sending request.
      hadd -m $sockname SOCK_STATE 3
      .signal -n WebSocket_REQSENT_ $+ %Name
    }

    ;; if there's data to send and room in the send buffer
    elseif ($bvar(&_WebSocket_SendBuffer, 0) && $sock($1).sq < 16384) {

      ;; determine amount of space in the buffer
      %Space = $calc($v2 - $v1)
      %Size = $bvar(&_WebSocket_SendBuffer, 0)

      ;; if there's enough space in the send buffer
      ;; add all pending data to it and delete the hashtable entry
      if (%Size <= %Space) {
        sockwrite $1 &_WebSocket_SendBuffer
        hdel $1 HTTPREQ_HEAD
        _WebSocket.Debug -i %Name $+ >REQ_SEND~Entire head now added to send buffer
      }

      ;; otherwise, add `%Space` bytes from the pending data to the write buffer
      ;; remove those bytes from the pending data and store the rest of the data
      else {
        sockwrite -b $1 %Space &_WebSocket_SendBuffer
        bcopy -c &_WebSocket_SendBuffer 1 &_WebSocket_SendBuffer $calc(%Space +1) -1
        hadd -mb $1 HTTPREQ_HEAD &_WebSocket_SendBuffer
        _WebSocket.Debug -i %Name $+ >REQ_SEND~Added %Space bytes of the head to the send buffer
      }
    }
  }

  ;; Frame-send handling
  ;;   Follows the same stepts as sending the HTTP request
  elseif ($hget($1, WSFRAME_Buffer, &_WebSocket_SendBuffer) && $sock($1).sq < 16384) {
    %Space = $calc($v2 - $v1)
    %Size = $bvar(&_WebSocket_SendBuffer, 0)
    if (%Size > %Space) {
      sockwrite -b $1 %Space &_WebSocket_SendBuffer
      bcopy -c &_WebSocket_SendBuffer 1 &_WebSocket_SendBuffer $calc(%Space +1) -1
      hadd -b $1 WSFRAME_Buffer &_WebSocket_SendBuffer
      _WebSocket.Debug -i %Name $+ >FRAME_SEND~Added %Space bytes of frame data to send buffer
    }
    
    else {
      sockwrite $1 &_WebSocket_SendBuffer
      hdel $1 WSFRAME_Buffer
      _WebSocket.Debug -i %Name $+ >FRAME_SEND~All pending frame data now in send buffer
    }
  }

  ;; handle errors
  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror
    _WebSocket.Debug -e %Name $+ >FRAME_SEND~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}

;; /_WebSocket.Cleanup sockname
;; frees up all resources related to the specified sockname
alias -l _WebSocket.Cleanup {
  var %Name = $gettok($1, 2-, 95)

  ;; cleanup sock and hashtable
  if ($sock($1)) {
    sockclose $1
  }
  if ($hget($1)) {
    hfree $1
  }

  ;; cleanup timer
  .timer_WebSocket_Timeout_ $+ %Name off

  ;; Raise finished event
  if ($show) {
    .signal -n WebSocket_FINISHED_ $+ %Name
  }
}

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