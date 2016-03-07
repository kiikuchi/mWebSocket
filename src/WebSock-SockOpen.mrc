
on $*:SOCKOPEN:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %Key, %Index

  _WebSocket.Debug -i2 SockOpen> $+ $sockname $+ ~Connection established

  ;; Initial error checking
  if ($sockerr) {
    %Error = SOCKOPEN_ERROR $sock($socknamw).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR socket-state hashtable doesn't exist
  }
  elseif ($hget($sockname, SOCK_STATE) != 1) {
    %Error = INTERNAL_ERROR State doesn't corrospond with connection attempt
  }
  elseif (!$len($hget($sockname, HTTPREQ_HOST))) {
    %Error = INTERNAL_ERROR State table does not contain host name
  }
  elseif (!$len($hget($Sockname, HTTPREQ_RES))) {
    %Error = INTERNAL_ERROR State table does not contain a resource to request
  }
  else {
    _WebSocket.Debug -i SockOpen> $+ %name $+ ~Preparing request head

    ;; Generate a Sec-WebSocket-Key
    bset &_WebSocket_SecWebSocketKey 1 $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255) $r(0,255)
    noop $encode(&_WebSocket_SecWebSocketKey, bm)
    hadd -mb $sockname HTTPREQ_SecWebSocketKey &_WebSocket_SecWebSocketKey
    
    bunset &_WebSocket_SecWebSocketKey &_WebSocket_HttpReq

    ;; Initial Request: Resource request and required Headers
    _WebSocket.BAdd &_WebSocket_HttpReq GET $hget($sockname, HTTPREQ_RES) HTTP/1.1
    _WebSocket.BAdd &_WebSocket_HttpReq Host: $hget($sockname, HTTPREQ_HOST)
    _WebSocket.BAdd &_WebSocket_HttpReq Connection: upgrade
    _WebSocket.BAdd &_WebSocket_HttpReq Upgrade: websocket
    _WebSocket.BAdd &_WebSocket_HttpReq Sec-WebSocket-Version: 13
    _WebSocket.BAdd &_WebSocket_HttpReq Sec-WebSocket-Key: $hget($sockname, HTTPREQ_SecWebSocketKey)

    ;; Raise init event so scripts can build header list
    .signal -n WebSocket_INIT_ $+ %Name

    ;; Loop over headers, adding them to the request
    %Index = 1
    while ($hfind($sockname, /^HTTPREQ_HEADER\d+_([^\s]+)$/, %Index, r)) {
      _WebSocket.BAdd &_WebSocket_HttpReq $regml(1) $hget($sockname, $v1)
      inc %Index
    }

    ;; Finalize the request head and store it
    _WebSocket.BAdd &_WebSocket_HttpReq
    hadd -b $sockname HTTPREQ_HEAD &_WebSocket_HttpReq
    bunset &_WebSocket_HttpReq

    ;; update state variable, output debug message and begin sending the request
    hadd $sockname SOCK_STATE 2
    _WebSocket.Debug -i SockOpen> $+ %Name $+ ~Sending HTTP request
    _WebSocket.Send $sockname
  }

  ;; Handle errors
  :error
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    %Error = $v1
    reseterror

    ;; Log error, raise error event, cleanup socket
    _WebSocket.Debug -e SockOpen> $+ %Name $+ ~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}