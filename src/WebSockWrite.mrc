;; /WebSockWrite -[c|p|P|b|t]+t name [data]
alias WebSockWrite {
  if ($isid) {
    return
  }

  var %FrameSwitch, %DataSwitch, %Name, %Sock, %Error, %Control = $false, %Code = 1, %Index, %Size, %MaskByte1, %MaskByte2, %MaskByte3, %MaskByte4

  ;; parse switches
  if ($left($1, 1) isin +-) {
    noop $regex($1, ^((?:-[^+]*)?)((?:+.*)?)$))
    %FrameSwitch = $mid($regml(1), 2-)
    %DataSwitch = $mid($regml(2), 2-)
    tokenize 32 $2-
  }

  %Name = $1
  %Sock = WebSocket_ $+ $1

  ;; validate switches
  if ($regex(%FrameSwitch, ([^cpPbt]))) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?\1)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%FrameSwitch, ([cpPbt]).*?([cpPbt]))) {
    %Error = Conflicting switches: $regml(1) $regml(2)
  }
  elseif ($regex(%DataSwitch, ([^t]))) {
    %Error = Invalid Data-force switch + $+ $regml(1)
  }

  ;; validate name parameter
  elseif (!$regex($1, ^(?!\d+$)[^?*]+$) || !$sock(%Sock)) {
    %Error = WebSocket does not exist
  }

  ;; validate socket state
  elseif (!$hget(%Sock) || !$len($hget(%Sock $+ $1, SOCK_STATE))) {
    hadd -m %Sock ERROR INTERNAL_ERROR State lost
    _WebSocket.Debug -e %Name $+ >STATE~State lost for %Name
    .signal -n WebSocket_Error_ $+ %Name
    _WebSocket.Cleanup %Sock
    %Error = State lost; connection ended
  }
  elseif ($hget(%Sock, SOCK_STATE) == 0 || $v1 == 5) {
    %Error = Connection in closing
  }
  elseif ($v1 !== 4) {
    %Error = WebSocket connection not established
  }
  elseif ($hget(%Sock, CLOSE_PENDING)) {
    %Error = Close frame sent; cannot add more frames
  }

  ;; Validate data
  elseif (%FrameSwitch isincs bt && $0 == 1) {
    %Error = No data to send
  }
  elseif (%DataSwitch !== t && &?* iswm $2 && $0 == 2 && (!$bvar($2, 0) || $bvar($2, 0) > 4294967295)) {
    %Error = Specified bvar doesn't exist, is empty or exceeds 4gb
  }
  else {

    ;; Frame-Type delegation
    if (c isincs %FrameSwitch) {
      %Control = $true
      %Code = 8
    }
    elseif (p isincs %FrameSwitch) {
      %Control = $true
      %Code = 9
    }
    elseif (p isincs %FrameSwitch) {
      %Control = $true
      %Code = 10
    }
    elseif (b isincs %FrameSwitch {
      %Code = 1
    }

    ;; Store data in bvar if need be
    bunset &Frame &FrameData
    if (t isin %DataSwitch || &?* !iswm $2 || $0 > 2) {
      %BVar = &FrameData
    }
    else {
      %BVar = $2
    }

    ;; store code: 1000 xxxx
    bset &Frame 1 $calc(128 + %Code)

    ;; If there is data to accompany the frame
    if ($Bvar(%BVar, 0)) {
      %Size = $v1
      %Index = 1

      ;; build payload-size field
      if (%Size < 126) {
        bset &Frame 2 $calc(128 + $v1)
      }
      elseif ($v1 isnum 126-65535) {
        bset &Frame 2 254 $regsubex($base($v1, 10, 2, 16), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }
      else {
        bset &Frame 2 255 $regsubex($base($v1, 10, 2, 64), /^(\d{8})/,$base(\t, 2, 10) $+ $chr(32))
      }

      ;; create masking bytes at random and append them to the frame
      %MaskByte1 = $r(0, 255)
      %MaskByte2 = $r(0, 255)
      %MaskByte3 = $r(0, 255)
      %MaskByte4 = $r(0, 255)
      bset &Frame $calc($bvar(&Frame, 0) + 1) %MaskByte1 %MaskByte2 %MaskByte3 %MaskByte4

      ;; loop over each byte of the frame's assocated data
      while (%Index <= %Size) {

        ;; mask the byte and append it to the frame
        bset &Frame $calc($bvar(&Frame, 0) + 1) $xor($bvar(%BVar, %Index), $($+(%, MaskByte, $calc((%Index - 1) % 4 + 1)), 2))
        inc %Index
      }
    }
    else {
      bset &Frame 2 0
    }

    ;; Add the frame to the send buffer, update state, and begin sending
    bunset &WSFRAME_Buffer
    noop $hget(%Sock, WSFRAME_Buffer, &WSFRAME_Buffer)
    bcopy -c &WSFRAME_Buffer $calc($bvar(&WSFRAME_Buffer, 0) + 1) &Frame 1 -1
    hadd -mb %Sock WSFRAME_Buffer &WSFRAME_Buffer
    bunset &Frame &WSFRAME_Buffer
    if (%Code === 8) {
      hadd -m %Sock CLOSE_PENDING $true
    }
    _WebSocket.Send %Sock
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    echo $color(info).dd -s * /WebSockWrite: $v1
    _WebSocket.Debug -e /WebSockWrite~ $+ $v1
    reseterror
    halt
  }
}

alias -l _WebSocket.Send {
  bunset &WebSocketSend

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

    ;; if the buffer and sendque is empty, the request has finished being set
    ;; output debug message, update state, and raise REQSENT event
    if (!$hget($1, HTTPREQ_HEAD, &WebSocketSend) && !$sock($1).sq) {
      _WebSocket.Debug -i2 %Name $+ >Head_Sent Finished sending request.
      hadd -m $sockname SOCK_STATE 3
      .signal -n WebSocket_REQSENT_ $+ %Name
    }

    ;; if there's data to send and room in the send buffer
    elseif ($bvar(&WebSocketSend, 0) && $sock($1).sq < 16384) {

      ;; determine amount of space in the buffer
      %Space = $calc($v2 - $v1)
      %Size = $bvar(&WebSocketSend, 0)

      ;; if there's enough space in the send buffer
      ;; add all pending data to it and delete the hashtable entry
      if (%Size <= %Space) {
        sockwrite $1 &WebSocketSend
        hdel $1 HTTPREQ_HEAD
        _WebSocket.Debug -i %Name $+ >HTTP_HEAD Entire head now added to send buffer
      }

      ;; otherwise, add `%Space` bytes from the pending data to the write buffer
      ;; remove those bytes from the pending data and store the rest of the data
      else {
        sockwrite -b $1 %Space &WebSocketSend
        bcopy -c &WebSocketSend 1 &WebSocketSend $calc(%Space +1) -1
        hadd -mb $1 HTTPREQ_HEAD &WebSocketSend
        _WebSocket.Debug -i %Name $+ >HEAD_SEND Added %Space bytes of the head to the send buffer
      }
    }
  }

  ;; Frame-send handling
  elseif ($hget($1, WSFRAME_Buffer, &WebSocketSend) && $sock($1).sq < 16384) {
    %Space = $calc($v2 - $v1)
    %Size = $bvar(&WebSocketSend, 0)
    if (%Size <= %Space) {
      sockwrite $1 &WebSocketSend
      hdel $1 WSFRAME_Buffer
      _WebSocket.Debug -i %Name $+ >FRAME_SEND All pending frame data now in send buffer
    }
    else {
      sockwrite -b $1 %Space &WebSocketSend
      bcopy -c &WebSocketSend 1 &WebSocketSend $calc(%Space +1) -1
      hadd -mb $1 WSFRAME_Buffer &WebSocketSend
      _WebSocket.Debug -i %Name $+ >FRAME_SEND add %Space bytes of frame data to send buffer
    }
  }

  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror
    _WebSocket.Debug -e %Name $+ >FRAME_SEND %Error
    _WebSocket.Cleanup $1
  }
}

on $*:SOCKWRITE:/^WebSocket_[^?*]*$/:{
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
    hadd -m $sockname ERROR %Error
    _WebSocket.debug -e %Name $+ >SOCKWRITE~ $+ %Error
    .signal WebSocket_ERROR_ $+ %Name
    _WebSocket.Cleanup $sockname
  }
}