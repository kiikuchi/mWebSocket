;; /WebSockOpen name uri [timeout]
alias WebSockOpen {
  if ($isid) {
    return
  }

  var %Error, %Sock, %Host, %Ssl, %Port

  ;; Validate inputs
  if ($0 < 2) {
    %Error = Missing paramters
  }
  elseif ($0 > 3) {
    %Error = Excessive Parameters
  }
  elseif (? isin $1 || * isin $1) {
    %Error = names cannot contain ? or *
  }
  elseif ($1 isnum) {
    %Error = names cannot be a numerical value
  }
  elseif ($sock(WebSocket_ $+ $1)) {
    %Error = specified 'name' in use
  }
  elseif ($0 == 3) && ($3 !isnum 1- || . isin $3 || $3 > 300) {
    %Error = Invalid timeout; must be an integer between 1 and 300
  }
  elseif (!$regex(uri, $2, /^((?:wss?:\/\/)?)([^?&#\/\\:]+)((?::\d+)?)((?:[\\\/][^#]*)?)(?:#.*)?$/i)) {
    %Error = Invalid URL specified
  }
  else {
    %Sock = WebSocket_ $+ $1
    %Host = $regml(uri, 2)

    ;; Cleanup after a non-existant socket just to be safe
    if ($hget(%Sock)) {
      ._WebSocket.Cleanup %Sock
    }

    ;; SSL determination
    if (wss:// == $regml(uri, 1)) {
      %Ssl = $true
    }
    else {
      %Ssl = $false
    }

    ;; Port determination
    if ($regml(uri, 3)) {
      %Port = $mid($v1, 2-)
      if (%Port !isnum 1-65535 || . isin %port) {
        %Error = Invalid port specified in uri; must be an interger to between 1 and 65,535
        goto error
      }
    }
    elseif (%Ssl) {
      %Port = 443
    }
    else {
      %Port = 80
    }

    ;; Store state variables
    hadd -m %Sock SOCK_STATE 1
    hadd -m %Sock SOCK_SSL %Ssl
    hadd -m %Sock SOCK_ADDR %Host
    hadd -m %Sock SOCK_PORT %Port
    hadd -m %Sock HTTPREQ_URI $2
    hadd -m %Sock HTTPREQ_RES $iif($len($regml(uri, 4)), $regml(uri, 4), /)
    hadd -m %Sock HTTPREQ_HOST %Host $+ $iif((%Ssl && %Port !== 443) || (!%Ssl && %Port !== 80), : $+ %Port)

    ;; Start timeout timer
    $+(.timer, WebSocket_Timeout_, $1) -oi 1 $iif($3, $v1, 300) _WebSocket.ConnectTimeout %Name

    ;; Begin socket connection and output debug message
    sockopen $iif(%ssl, -e) %sock %host %port
    _WebSocket.Debug -i Connecting> $+ $1 $+ ~Connecting to %host $iif(%ssl, with an SSL connection) on port %port as %sock
  }

  ;; Handle errors
  :error
  if ($error || %error) {
    echo $color(info).dd -s * /WebSockOpen: $v1
    _WebSocket.Debug -e /WebSockOpen~ $+ $v1
    reseterror
    halt
  }
}

;; /_WebSocket.ConnectTimeout name
;; closes a connection that took too long to establish
alias -l _WebSocket.ConnectTimeout {
  if ($isid) {
    return
  }

  ;; output debug message, raise error event, cleanup
  _WebSocket.Debug -e $1 $+ >TIMEOUT Connection timed out
  .signal -n WebSocket_Error_ $+ $1 $1 SOCK_ERROR Connection timeout
  _WebSocket.Cleanup WebSocket_ $+ $1
}

on $*:SOCKOPEN:/^WebSocket_[^\d?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %Key, %Index

  _WebSocket.Debug -i2 SockOpen> $+ $sockname $+ ~Connection established

  ;; Initial error checking
  if ($sockerr) {
    %Error = SOCKOPEN_ERROR $sock($socknamw).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR socket-state hashtable doesn't exist
  }
  elseif ($hget($sockname, SOCK_STATE) !== 1 || !$hget($sockname, HTTPREQ_HOST) || !$hget($Sockname, HTTP_RES)) {
    %Error = INTERNAL_ERROR State doesn't corrospond with attempting to connect
  }
  else {
    _WebSocket.Debug -i SockOpen> $+ %name $+ ~Preparing request head

    ;; Generate a Sec-WebSocket-Key
    bset &SecWebSocketKey 1 $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255) $r(1,255)
    noop $encode(&SecWebSocketKey, bm)
    hadd -mb $sockname HTTPREQ_SecWebSocketKey &SecWebSocketKey
    bunset &SecWebSocketKey

    ;; Initial Request: Resource request and required Headers
    hadd -m $sockname HTTPREQ_SecWebSocketKey $_WebSocket.SecKey
    bunset &HTTPREQ
    _WebSocket.BAdd &HTTPREQ GET $hget($sockname, HTTPREQ_RESOURCE) HTTP/1.1
    _WebSocket.BAdd &HTTPREQ Host: $hget($sockname, HTTPREQ_HOST)
    _WebSocket.BAdd &HTTPREQ Connection: upgrade
    _WebSocket.BAdd &HTTPREQ Upgrade: websocket
    _WebSocket.BAdd &HTTPREQ Sec-WebSocket-Version: 13
    _WebSocket.BAdd &HTTPREQ Sec-WebSocket-Key: $hget($sockname, HTTPREQ_SecWebSocketKey)

    ;; Raise init event so scripts can build header list
    .signal -n WebSocket_INIT_ $+ %Name %Name

    ;; Loop over headers, adding them to the request
    %Index = 1
    while ($hfind($sockname, /^HTTPREQ_HEADER\d+_([^\s]+)$/, %Index, r)) {
      _WebSocket.BAdd &HTTPREQ $regml(1) $hget($sockname, $v1)
      inc %Index
    }

    ;; Finalize the request, store the request, and update state variable
    _WebSocket.BAdd &HTTPREQ
    hadd -mb $sockname HTTPREQ_HEAD &HTTPREQ
    hadd -m $sockname SOCK_STATE 2

    ;; Output debug message and begin sending the request
    _WebSocket.Debug -i SockOpen> $+ %Name $+ ~Sending HTTP request
    _WebSocket.Send $sockname
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror

    ;; Log error, raise error event, cleanup socket
    _WebSocket.Debug -e SockOpen> $+ %Name $+ ~ $+ %Error
    .signal -n WebSocket_ERROR_ $+ %Name %Name %Error
    hadd -m $sockname SOCK_STATE 0
    _WebSocket.Cleanup $sockname
  }
}
on $*:SOCKREAD:/^WebSocket_[^?*]+$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %HeadData, %Index, %SecAccept, %HeadSize, %FragSize

  ;; Basic Error checks
  if ($sockerr) {
    %Error = SOCKREAD_ERROR $sock($sockname).wsmsg
  }
  elseif (!$hget($sockname)) {
    %Error = INTERNAL_ERROR State lost
  }
  elseif ($hget($sockname, SOCK_STATE) == 5) {
    %Error = FRAME_ERROR Frame recieved after a CLOSE frame has been recieved.
  }

  ;;----------------------------;;
  ;;    Handshake Processing    ;;
  ;;----------------------------;;
  elseif ($v1 == 3) {

    ;; make sure the key sent to the server with the request is still accessible
    if (!$hget($sockname, HTTPREQ_SecWebSocketKey)) {
      %Error = INTERNAL_ERROR State lost (Sec-WebSocket-Key Not Found)
    }
    else {

      ;; read the buffer data line-by-line
      sockread %HeadData
      while ($sockbr) {

        ;; Trim whitespace from the data
        %HeadData = $regsubex(%HeadData, /(?:^\s+)|(?:\s+$)/g, )

        ;; Check that there's data after trimming whitespace
        if (%HeadData) {

          ;; if the status line has not been read
          if (!$hget($sockname, HTTPRESP_StatusCode)) {

            ;; Check the line's format, and if its valid store required portions of it
            if ($regex(%HeadData, /^(HTTP\/(?:0\.9|1\.[01])) (\d+)((?:\s.*)?)[\r\n]*$/i)) {
              hadd -m $sockname HTTPRESP_HttpVersion $regml(1)
              hadd -m $sockname HTTPRESP_StatusCode $regml(2)
              hadd -m $sockname HTTPRESP_StatusText $iif($regml(3), $v1, _NONE_)
            }

            ;; otherwise, store error and exit looping
            else {
              %Error = HTTP_ERROR Status line invalid: %HeadData
            }
          }

          ;; If the status line has been received, assume the current line is a header
          ;;   Validate the header's format, get an index to store the header under, store it, and output debug message
          elseif ($regex(header, %HeadData, ^(\S+): (.*)$)) {
            %Index = $calc($hfind($sockname, HTTPRESP_HEADER?*_*, w, 0) + 1)
            hadd -m $sockname $+(HTTPRESP_HEADER, %Index, _, $regml(header, 1)) $regml(header, 2)
            _WebSocket.Debug -i %Name $+ >HEADER~Header Received: $regml(header, 1) $+ : $regml(header, 2)
          }

          ;; If the current line isn't a correctly formatted error
          ;;   store the error and exit looping
          else {
            %Error = HTTP_ERROR Response contained an invalid header
          }
        }

        ;; If the HTTP version is not HTTP/1.1
        elseif ($hget($sockname, HTTPRESP_HttpVer) !== HTTP/1.1) {
          %Error = HTTP_ERROR Unacceptable HTTP version: $v1
        }

        ;; If the server did not return an upgrade response code
        elseif ($hget($sockname, HTTPRESP_StatusCode) !== 101) {
          %Error = HTTP_ERROR Response does not wish to upgrade
        }

        ;; If the server did not return a "Connection: Upgrade" header
        elseif ($hfind($sockname, HTTPRESP_Header?*_Connection, 1, w) == $null || $hget($sockname, $v1) !== Upgrade) {
          %Error = HTTP_ERROR Connection header not received or not "Upgrade"
        }

        ;; if the server did not return a "Upgrade: websocket" header
        elseif ($hfind($sockname, HTTPRESP_Header?*_Upgrade, 1, w) == $null || $hget($sockname, $v1) !== websocket) {
          %Error = HTTP_ERROR Upgrade header not received or not "websocket"
        }

        ;; If the server did not return a "Sec-WebSocket-Accept" header
        elseif ($hfind($sockname, HTTPRESP_Header?*_Sec-WebSocket-Accept, 1, w) == $null) {
          %Error = HTTP_ERROR Sec-WebSocket-Accept header not received
        }

        ;; no errors so far
        else {
          %SecAccept = $hget($sockname, $v1)

          ;; Digest the key that was sent to the server
          bunset &SecWebSockAccept
          bset &SecWebSockAccept 1 $regsubex($sha1($hget($sockname, HTTPREQ_SecWebSocketKey) $+ 258EAFA5-E914-47DA-95CA-C5AB0DC85B11), /(..)/g, $base(\t, 16, 10) $+ $chr(32))
          noop $encode(&WebSockKeyDigest, mb)

          ;; ERROR - The response security key does not match the digest of the sent key
          if (%SecAccept !== $bvar(&WebSockKeyDigest, 1-).text) {
            %Error = HTTP_ERROR Sec-WebSocket-Accept header value does not match digested key
          }

          ;; SUCCESS! - Head received and contains approiate data
          ;;   Stop timeout timer, update state variable, output debug message, raise event
          else {
            $+(.timer, WebSocket_Timeout_, %Name) off
            hadd -m $sockname SOCK_STATE 4
            _WebSocket.Debug -s %Name $+ >HANDSHAKE~Handshake complete; ready to send and recieve frames!
            .signal -n WebSocket_READY_ $+ %Name %Name
          }
        }

        ;; if an error occured, exit the loop
        if (%Error || $hget($sockname, SOCK_STATE) == 4) {
          break
        }

        ;; read the next line in the buffer
        sockread %HeadData
      }
    }
  }

  ;;------------------------;;
  ;;    Frame processing    ;;
  ;;------------------------;;
  elseif ($hget($sockname, SOCK_STATE) == 4) {

    ;; read all data in socket buffer
    sockread $sock($sockname).rq &RecvData

    ;; append data to what is is the pending frame buffer
    noop $hget($sockname, WSFRAME_PENDING, &Buffer)
    bcopy -c &Buffer $calc($bvar(&Buffer, 0) + 1) &RecvData 1 -1

    ;; cleanup before processing
    bunset &RecvData

    ;; Begin looping over the buffer data to seperate frames
    while ($bvar(&Buffer, 0) >= 2) {
      %HeadData = $bvar(&RecvData, 1, 1)
      %HeadSize = 2
      %FragSize = $base(&RecvData, 2, 1)

      ;; ERROR - CLOSE frame previously recieved; subsequent frames should not have been sent
      if ($hget($sockname, SOCK_STATE) == 5) {
        %Error = FRAME_ERROR Frame recieved after a CLOSE frame has been recieved.
      }

      ;; ERROR - Frame makes use of reserved bits (bit2, bit3, or bit4)
      elseif ($isbit(%HeadData, 5) || $isbit(%HeadData, 6) || $isbit(%HeadData, 7)) {
        %Error = FRAME_ERROR Frame used RSV bits
      }

      ;; ERROR - Frame head indicates a fragmented(bit1 = 0) control-frame(bit5 = 1)
      elseif (!$isbit(%Head, 8) && $isbit(%HeadData, 4)) {
        %Error = FRAME_ERROR Fregmented control frame
      }

      ;; ERROR - Frame head indicates a control-frame that isn't:
      ;;   CLOSE(bit5-8 = 8), PING(bit5-8 = 9), or PONG(bit5-8 = 10)
      elseif ($isbit(%HeadData, 4) && %HeadData !isnum 136-138) {
        %Error = FRAME_ERROR Recieved unknown control-frame type
      }

      ;; ERROR - Frame head indicates the frame is a data-type that isn't:
      ;;   TEXT(bit5-8 = 1) or BINARY(bit5-8 = 2)
      elseif (!$isbit(%HeadData, 4) && $calc(%HeadData % 128) !isnum 1-2) {
        %Error = FRAME_ERROR Received unknown data-frame type
      }

      ;; ERROR - Frame head indicates the data is masked(bit9 = 1)
      elseif ($isbit(%FragSize, 8)) {
        %Error = FRAME_ERROR Received masked frame from server
      }

      ;; ERROR - Frame indicates its data-type is not that of the previously received frame fragment
      elseif (!$isBit(%HeadData, 4) && $hget($sockname, WSFRAME_FragmentType) && $v1 !== $calc(%HeadData % 128)) {
        %Error = FRAME_ERROR Recieved Mixed frame data-type fragments
      }

      ;; ERROR - Frame's data length would overflow a 32bit integer
      ;;   the largest mIRC can safely handle
      elseif (%FragSize == 127 && $bvar(&RecvData, 0) >= 6 && $bvar(&RecvData, 3).nlong !== 0) {
        %Error = FRAME_ERROR Data size would overflow an int32
      }
      else {

        ;; If the 2nd octlet is equal to 126, the fragment size is the following 2 octlets
        ;;   Make sure the entire frame head has been recieved, and update size variables
        if (%FragSize == 126) {
          if ($bvar(&RecvData, 0) < 4) {
            break
          }
          %HeadSize = 4
          %FragSize = $_WebSocket.ToInt($bvar(&RecvData, 3, 2))
        }

        ;; If the 2nd octlet is equal to 127, the fragment size the the following 8 octlets
        ;;   Make sure the entire frame head has been recieved, and update size variables
        elseif (%DataSize == 127) {
          if ($bvar(&RecvData, 0) < 10) {
            break
          }
          %HeadSize = 10
          %FragSize = $bvar(&RecvData, 7).nlong
        }

        ;; Check to verify the entire frame has been read
        if ($bvar(&RecvData, 0) < $calc(%HeadSize + %FragSize)) {
          break
        }

        ;; Retrieve previously stored fragment data, then remove it from the hashtable
        bunset &FrameData
        noop $hget($sockname, WSFRAME_Fragment, &FrameData)
        hdel $sockname WSFRAME_Fragment
        hdel $sockname WSFRAME_FragmentType

        ;; Copy the new Frame's data to the stored frame parts, then remove the frame from the received buffer
        bcopy -c &FrameData $calc($bvar(&FrameData, 0) + 1) &RecvData $calc(%HeadSize + 1) %FragSize
        if ($calc(%HeadSize + %FragSize) == $bvar(&RecvData, 0)) {
          bunset &RecvData
        }
        else {
          bcopy -c &RecvData 1 &RecvData $calc($v1 +1) -1
        }

        ;; Control-Frame (CLOSE)
        if (%HeadData == 136) {

          ;; ERROR - if there's data following the close frame, the connection is errorous
          if ($bvar(&RecvData, 0)) {
            %Error = %Error = FRAME_ERROR Data recieved after a CLOSE frame has been recieved.
          }

          ;; If the client sent a close frame and the server responded:
          ;;   Otherwise: output debug message, raise event, cleanup after the connection, exit processing
          elseif ($hget($sockname, CLOSE_PENDING)) {
            _WebSocket.Debug -i2 %Name $+ >FRAME:CLOSE~Close frame reply received; closing connection.
            .signal -n WebSocket_CLOSE_ $+ %Name %Name &FrameData
            _WebSocket.Cleanup $sockname
          }

          ;; The close frame is unsoliated:
          ;;   Output debug message, raise closing event, update sock state, and queue close frame
          else {
            _WebSocket.Debug -i %Name $+ >FRAME:CLOSE~Close frame received.
            .signal -n WebSocket_CLOSING_ $+ %Name %Name &FrameData
            hadd -m $sockname SOCK_STATE 5
            WebSockClose $sockname
          }
          break
        }

        ;; Control-Frame (PING)
        ;;   Output debug message, raise Ping event, queue pong frame
        elseif (%HeadData == 137) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Ping frame received.
          .signal -n WebSocket_PING_ $+ %Name %Name &FrameData
          WebSockWrite -P $sockname &FrameData
        }

        ;; Control-Frame (PONG)
        elseif (%HeadData == 138) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Pong frame received.
          .signal -n WebSocket_PONG_ $+ %Name %Name &FrameData
        }

        ;; if the frame is not a final-fragment, store the data for the next frame read
        else if (!$isbit(%HeadData, 8)) {
          hadd -mb $sockname WSFRAME_Fragment &FrameData
          hadd -m $sockname  WSFRAME_FragmentType $calc(%HeadData % 128)
        }

        ;; Data-Frame: TEXT(129) or BINARY(130)
        elseif (%HeadData == 129 || %HeadData == 130) {
          _WebSocket.Debug -i %Name $+ >FRAME:Data~ $+ $iif(%HeadData == 129, Text, Binary) frame recieved
          .signal -n WebSocket_DATA_ $+ %Name %Name &FrameData $calc(%HeadData % 128)
        }
      }

      ;; if an error occured, exit looping
      if (%Error) {
        break
      }
    }

    ;; If no errors occured, update the buffer
    if (!%Error) {
      if ($bvar(&Buffer, 0)) {
        hadd -mb $sockname WSFRAME_PENDING &Buffer
      }
      elseif ($hget($sockname, WSFRAME_PENDING).item) {
        hdel $sockname WSFRAME_PENDING
      }
    }
  }
  elseif ($v1 !== 0) {
    %Error = INTERNAL_ERROR State variable mixmatch
  }

  ;; Handle errors
  :error
  if ($error || %Error) {
    %Error = $v1
    reseterror

    ;; Log error, Raise Event, then cleanup
    _WebSocket.Debug -e SockRead> $+ %Name $+ ~ $+ %Error
    .signal -n WebSocket_ERROR_ $+ %Name %Name %Error
    _WebSocket.Cleanup $sockname
  }
}
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
    _WebSocket.Debug -e %Name $+ >STATE~State lost for %Name
    .signal -n WebSocket_Error_ $+ %Name %Name INTERNAL_ERROR State Lost
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
        bset &Frame $calc($bvar(&Frame, 0) + 1) $xor($bvar(%BVar, %Index), $($+(%, M, $calc((%Index - 1) % 4 + 1)), 2))
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
  elseif ($hget($1, SOCK_STATE) !== 3) {
    %Error = INTERNAL_ERROR State doesn't match data sending
  }

  ;; HTTP Request send handling
  elseif ($v1 === 2) {

    ;; if the buffer and sendque is empty, the request has finished being set
    ;; output debug message, update state, and raise REQSENT event
    if (!$hget($1, HTTPREQ_HEAD, &WebSocketSend) && !$sock($1).sq) {
      _WebSocket.Debug -i2 %Name $+ >Head_Sent Finished sending request.
      hadd -m $sockname SOCK_STATE 3
      .signal -n WebSocket_REQSENT_ $+ %Name %Name
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
  if ($error || %Error) {
    %Error = $v1
    reseterror
    _WebSocket.debug -e %Name $+ >SOCKWRITE~ $+ %Error
    .signal WebSocket_ERROR_ $+ %Name %Name
    _WebSocket.Cleanup $sockname
  }
}

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
    .signal -n WebSocket_FINISHED_ $+ %Name %Name
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
  if ($error || %Error) {
    %Error = $v1
    reseterror
    _WebSocket.Debug -e %Name $+ >SOCKCLOSE~ $+ %Error
    .signal -n WebSocket_ERROR_ $+ %Name %Name %Error
  }

  ;; otherwise, report successful close
  else {
    _WebSocket.Debug -s %Name $+ >SOCKCLOSE~Connection Closed
    .signal -n WebSocket_CLOSE_ $+ %Name %Name
  }

  ;; cleanup
  _WebSocket.Cleanup $sockname
}
alias WebSock {
  if (!$isid) {
    return
  }

  var %Name, %Sock, %State, %Find, %Index, %Header

  ;; Deduce the name to use
  if (!$0) {
    if ($event !== signal && !$regex($signal, ^WebSocket_[A-Z]+_(?!-)(?!\d*$)(.*)$)) {
      return
    }
    %Name = $regml(1)
  }
  elseif ($regex(name, $1, ^(?!-)(?!\d*$)(.*)$)) {
    %Name = $regml(name, 1)
  }
  else {
    return
  }

  %Sock = WebSocket_ $+ %Name

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
      return SENDING_REQUEST
    }
    elseif (%State == 3) {
      return RESPONSE_PENDING
    }
    elseif (%State == 4) {
      return READY
    }
    elseif (%State == 5) {
      return WEBSOCKET_CLOSING
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
    return $hget(%Sock, SOCK_URI))
  }

  ;; $WebSock().HttpVersion
  elseif ($prop == HttpVersion) {
    return $hget(%Sock, HTTPRESP_HttpVersion)
  }

  ;; $WebSock().HttpStatus
  elseif ($prop == HttpStatus) {
    return $hget(%Sock, HTTPRESP_StatusCode)
  }

  ;; $WebSock().HttpStatusText
  elseif ($prop == HttpStatusText) {
    return $hget(%Sock, HTTPRESP_StatusText)
  }

  ;; $WebSock().Headers
  elseif ($prop == Headers) {
    return $hfind(%Sock, ^HTTPRESP_HEADER\d+_, 0, r)
  }

  ;; $WebSock().HttpHeader
  elseif ($prop == HttpHeader) {
    if (!$hget(%Sock) || $0 < 2 || ($0 == 3 && ($3 !isnum 0- || . isin $3)) || $0 > 3) {
      return
    }

    ;; $WebSock(name, header[, n]).HttpHeader
    elseif ($0 == 3 || $2 !isnum 0- || . isin $2) {
      %Header = $hfind(%Sock, ^HTTPRESP_HEADER\d+_\Q $+ $replacecs($2, \E, \Q\\E\E) $+ \E$, $iif($0 == 3, $v1, 1), r)
      if (!%index) {
        return %Header
      }
      return $hget(%Sock, %Header)
    }

    ;; $WebSock(name, n).HttpHeader
    elseif ($2) {
      return $gettok($hfind(%Sock, ^HTTPRESP_HEADER $+ $2 $+ _, 1, r), 3-, 95)
    }
    else {
      return $hfind(%Sock, ^HTTPRESP_HEADER\d+_, 0, r)
    }
  }
}

;; /WebSockHeader Header Value
alias WebSockHeader {
  var %Error, %Name, %Sock
  if ($isid || !$event !== signal || !$regex(name, $signal, ^WebSocket_INIT_(?!-)(?!\d*$)(.*)$)) {
    return
  }
  else {
    %Name = $regml(name, 1)
    %Sock = WebSocket_ $+ %Name

    if (!$sock(%Sock)) {
      %Error = WebSocket not in use
    }
    elseif ($0 !== 2) {
      %Error = Missing parameters
    }
    else {
      %Header = $regsubex($1, /(?:^\s)(?:\s*:\s*$)/g, )
      if (!$len(%Header)) {
        %Error = Invalid header name
      }
      else {
        %Index = $calc($hfind(%Sock, ^HTTPREQ_HEADER\d+_, 0, r) + 1)
        hadd -m %Sock $+(HTTPREQ_HEADER, %Index, _, %Header) %Value
      }
    }
  }

  :error
  if ($error || %Error) {
    echo -sg * /WebSockHeader: $v1
    reseterror
    halt
  }
}


;; /WebSockDebug [on|off]
;; $WebSockDebug
alias WebSockDebug {

  ;; If identifier, return the debug state
  if ($isid) {
    return $iif($group(#WebSocket_Debug) == on, $true, $false)
  }

  ;; Toggle debug group according to input
  if ($1 == on || $1 == enable) {
    .enable #WebSocket_Debug
  }
  elseif ($1 == off || $1 == disable) {
    .disable #WebSocket_Debug
  }
  elseif (!$0) {
    $iif($group(#WebSocket_Debug) == on, .disable, .enable) #WebSocket_Debug
  }
  else {
    echo -gs * /WebSockDebug: Invalid input
    halt
  }

  ;; create debug window if required
  if ($group(#WebSocket_Debug) == on && !$window(@WebSocketDebug)) {
    window -nzk0 @WebSocketDebug
  }
}

;; /_WebSocket.BAdd &bvar text
;; adds the specified text to the end of the bvar
alias -l _WebSocket.BAdd {
  bvar -t $1 $calc($bvar($1, 0) + 1) $2- $+ $crlf
}

;; if the group is on the contained alias is used for outputting debug messages:
;; /_WebSocket.Debug -ewiNs [title~][msg]
#WebSocket_Debug on
alias -l _WebSocket.Debug {

  ;; if the debug window isn't open, disable debugging
  if (!$window(@WebSocketDebug)) {
    .disable #WebSocket_Debug
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
#WebSocket_Debug end

;; if the group is off this alias is used for outputting debug messages which do nothing:
alias -l _WebSocket.Debug

;; menu for the debug window
menu @WebSocketDebug {
  $iif($WebSockDebug, Disable, Enable): WebSocketDebug
  -
  Save: noop
  Clear:clear @WebSocketDebug
  -
  Close: .disable #WebSocket_Debug | close -@ @WebSocketDebug
}

;; if the debug window gets closed, disable debugging
on *:CLOSE:@WebSocketDebug:{
  .disable #WebSocket_Debug
}