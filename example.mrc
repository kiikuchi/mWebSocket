alias wstest {
  ;; force close the current example websocket if it exists
  if ($WebSock(wstest)) {
    WebSockClose -f wstest
  }

  ;; create a new example websocket
  WebSockOpen wstest ws://echo.websocket.org/
}



;; INIT event raised when the socket(not to be confused with websocket)
;; connection has been established. You do not need to specify this event
;; unless you intend/need to set request headers.
;;
;; You can specify headers to send with the request via the use of
;; /WebSockHeader <header-name> <value>
on *:SIGNAL:WebSocket_INIT_wstest:{

  ;; Output state-change message
  echo 10 -s [wstest>INIT] Connection established

  ;; Output information about the websock
  echo 03 -s [wstest>INIT] Name:      $WebSock
  echo 03 -s [wstest>INIT] State:     $WebSock(wstest).State
  echo 03 -s [wstest>INIT] StateText: $WebSock(wstest).StateText
  echo 03 -s [wstest>INIT] SSL:       $WebSock(wstest).Ssl
  echo 03 -s [wstest>INIT] Host:      $WebSock(wstest).host
  echo 03 -s [wstest>INIT] Port:      $WebSock(wstest).port
  echo 03 -s [wstest>INIT] Uri:       $WebSock(wstest).uri
  echo -s -
}


on *:SIGNAL:WebSocket_REQSENT_wstest:{

  ;; Output state-change message
  echo 10 -s [wstest>REQSENT] Request sent
}

;; READY event raised after the handshake has successuflly completed and
;; the connection is ready to transfer websocket frame data.
;;
;; /WebSockWrite can be used to send data frames to the server
on *:SIGNAL:WebSocket_READY_wstest:{

  ;; Output state-change message
  echo 12 -s [wstest>READY] Handshake Complete

  ;; Output information about the websock
  echo 03 -s [wstest>READY] HTTP Version: $WebSock(wstest).HttpVersion
  echo 03 -s [wstest>READY] Status Code:  $WebSock(wstest).StatusCode
  echo 03 -s [wstest>READY] Status Text:  $WebSock(wstest).StatusText

  ;; Loop over each HTTP header recieved from the server
  var %i = 1, %n, %h = $WebSock(wstest, 0).HttpHeader
  echo 03 -s [wstest>HEADER] Count: %h
  while (%i <= %h) {

    ;; Output the header
    %n = $WebSock(wstest, %i).HttpHeader
    echo 03 -s [wstest>HEADER] Header %n $+ : $WebSock(wstest, %n, 1).HttpHeader
    inc %i
  }
  echo -s -

  ;; Since the handshake is complete, /WebSockWrite can be used to send
  ;; data to the server
  WebSockWrite +t $WebSock abc
}

on *:SIGNAL:WebSocket_DATA_wstest:{
  echo 10 -s [wstest>DATA] $WebSockTypeText $+ ( $+ $WebSockType $+ ) frame recieved $+ $iif($WebSockText, : $v1, .)
}
on *:SIGNAL:WebSocket_ERROR_wstest:{
  echo 04 -s [wstest>ERROR] Error: $WebSockErr > $WebSockErrMsg
}
on *:SIGNAL:WebSOcket_CLOSING_wstest:{
  echo 07 -s [wstest>CLOSING] $WebSockTypeText $+ ( $+ $WebSockType $+ ) frame recieved $+ $iif($WebSockText, : $v1, .)
}
on *:SIGNAL:WebSocket_CLOSE_wstest:{
  echo 07 -s [wstest>CLOSE] Connection closed.
}
on *:SIGNAL:WebSocket_FINISHED_wstest:{
  echo 12 -s [wstest>FINISHED] All resources freed
}
