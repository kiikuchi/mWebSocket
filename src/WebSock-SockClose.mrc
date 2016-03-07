on $*:SOCKCLOSE:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
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
    _WebSocket.Debug -e %Name $+ >SOCKCLOSE~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }

  ;; otherwise, report successful close
  else {
    _WebSocket.Debug -s %Name $+ >SOCKCLOSE~Connection Closed
    .signal -n WebSocket_CLOSE_ $+ %Name
  }

  ;; cleanup
  _WebSocket.Cleanup $sockname
}