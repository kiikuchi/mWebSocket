;; /WebSockClose -f sockname
alias WebSockClose {
  var %Switches, %Error, %Name = $1, %Sock = WebSocket_ $+ %Name

  if (-* iswm $1) {
    %Switches = $mid($1, 2-)
    tokenize 32 $2-
  }

  ;; validate switches
  if ($regex(%Switches, ([^f]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif (%Switches === ff) {
    %Error = Duplicate switch specified: f
  }
  elseif ($0 > 1) {
    %Error = Excessive parameters
  }

  ;; validate sockname
  elseif (!$regex($1, ^(?!-?\d+$).+$)) {
    %Error = Invalid websocket name
  }
  elseif (!$sock(%Sock)) {
    ._WebSocket.Cleanup %Sock
    %Error = WebSocket does not exist
  }

  ;; if its a force close, cleanup the sock
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
    WebSockWrite -c %Sock
  }

  :error
  if ($error || %Error) {
    echo -sg * /WebSockClose: $v1
    reseterror
    halt
  }
}

;; /_WebSocket.Cleanup sockname
;; frees up all resources related to the specified sockname
alias -l _WebSocket.Cleanup {
  var %Name = $gettok($1, 2-, 95)

  ;; cleanup sock and hashtable
  if ($sock($1)) sockclose $1
  if ($hget($1)) hfree -w $1

  ;; cleanup timer
  .timerWebSocket_Timeout_ $+ %Name off

  ;; Raise finished event
  if ($show) {
    .signal -n WebSocket_FINISHED_ $+ %Name
  }
}

on $*:SOCKCLOSE:/^WebSocket_[^\d?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95)

  ;; Basic error checks
  if ($sockerr) {
    %Error = SOCK_ERROR $sock($sockname).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR state lost (hashtable does not exist)
  }

  ;; Check to make sure a close frame was processed
  elseif (!$hget($sockname, state) !== 5) {
    %Error = SOCK_ERROR Connection closed without recieving a CLOSE frame
  }

  ;; handle errors
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    hadd -m $sockname ERROR %Error
    _WebSocket.Debug -e %Name $+ >SOCKCLOSE~ $+ %Error
    .signal -n WebSocket_ERROR_ $+ %Name
  }

  ;; otherwise, report successful close
  else {
    _WebSocket.Debug -s %Name $+ >SOCKCLOSE~Connection Closed
    .signal -n WebSocket_CLOSE_ $+ %Name
  }

  ;; cleanup
  _WebSocket.Cleanup $sockname
}