on $*:SOCKWRITE:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %State = $hget($sockname, SOCK_STATE)

  ;; Check for errors
  if ($sockerr) {
    %Error = SOCK_ERROR Failed to write to connection
  }
  elseif (!$hget($sockname) || !$len(%State)) {
    %Error = INTERNAL_ERROR State lost
  }
  elseif (%State !== 2 && %State !== 4 && %State !== 5) {
    %Error = INTERNAL_ERROR State doesn't corrospond with data-send attempt: %State
  }

  ;; Attempt to send more data
  else {
    _WebSocket.Send $sockname
  }

  ;; Handle errors
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    _WebSocket.debug -e %Name $+ >SOCKWRITE~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}