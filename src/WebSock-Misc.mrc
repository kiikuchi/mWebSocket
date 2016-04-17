;; if the group is off this alias is used for outputting debug messages which do nothing:
alias -l _WebSocket.Debug

;; menu for the debug window
menu @WebSocketDebug {
  $iif($WebSockDebug, Disable, Enable): WebSocketDebug
  -
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