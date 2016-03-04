alias wstest {
  if ($WebSock(wstest)) {
    WebSockClose -f wstest
  }
  WebSockOpen wstest ws://echo.websocket.org/
}

on *:SIGNAL:WebSocket_INIT_wstest:{
  echo 10 -s [wstest>INIT] Connection established

  var %e = echo 03 -s [wstest>INIT]
  %e Name:      $WebSock
  %e State:     $WebSock(wstest).State
  %e StateText: $WebSock(wstest).StateText
  %e SSL:       $WebSock(wstest).Ssl
  %e Host:      $WebSock(wstest).host
  %e Port:      $WebSock(wstest).port
  %e Uri:       $WebSock(wstest).uri
  echo -s -
}
on *:SIGNAL:WebSocket_REQSENT_wstest:{
  echo 10 -s [wstest>REQSENT] Request sent

  var %e = echo 03 -s [wstest>REQSENT]
  %e Name:      $WebSock
  %e State:     $WebSock(wstest).State
  %e StateText: $WebSock(wstest).StateText
  %e SSL:       $WebSock(wstest).Ssl
  %e Host:      $WebSock(wstest).host
  %e Port:      $WebSock(wstest).port
  %e Uri:       $WebSock(wstest).uri
  echo -s -
}
on *:SIGNAL:WebSocket_READY_wstest:{
  echo 12 -s [wstest>READY] Handshake Complete
  var %e = echo 03 -s [wstest>READY], %i = 1, %n, %h
  %e Name:      $WebSock
  %e State:     $WebSock(wstest).State
  %e StateText: $WebSock(wstest).StateText
  %e SSL:       $WebSock(wstest).Ssl
  %e Host:      $WebSock(wstest).host
  %e Port:      $WebSock(wstest).port
  %e Uri:       $WebSock(wstest).uri
  %e HTTP Version: $WebSock(wstest).HttpVersion
  %e Status Code:  $WebSock(wstest).StatusCode
  %e Status Text:  $WebSock(wstest).StatusText
  %h = $WebSock(wstest, 0).HttpHeader
  %e = echo 03 -s [wstest>HEADER]
  %e Count: %h
  while (%i <= %h) {
    %n = $WebSock(wstest, %i).HttpHeader
    %e Header %n $+ : $WebSock(wstest, %n, 1).HttpHeader
    inc %i
  }
  echo -s -

  WebSockWrite +t $WebSock abc
}
on *:SIGNAL:WebSocket_PING_wstest:{
  echo 10 -s [wstest>PING] $WebSockTypeText $+ ( $+ $WebSockType $+ ) frame recieved $+ $iif($WebSockText, : $v1, .)
}
on *:SIGNAL:WebSocket_PONG_wstest:{
  echo 10 -s [wstest>PONG] $WebSockTypeText $+ ( $+ $WebSockType $+ ) frame recieved $+ $iif($WebSockText, : $v1, .)
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
