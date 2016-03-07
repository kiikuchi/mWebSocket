on $*:SOCKREAD:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
  var %Error, %Name = $gettok($sockname, 2-, 95), %HeadData, %Index, %SecAccept, %HeadSize, %Header, %IsFinal, %RSVBits, %IsControl, %FrameType, %DataSize

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
          if (!$len($hget($sockname, HTTPRESP_StatusCode))) {

            ;; Check the line's format, and if its valid store required portions of it
            if ($regex(%HeadData, /^HTTP\/(0\.9|1\.[01]) (\d+)((?:\s.*)?)[\r\n]*$/i)) {
              hadd $sockname HTTPRESP_HttpVersion $regml(1)
              hadd $sockname HTTPRESP_StatusCode $regml(2)
              hadd $sockname HTTPRESP_StatusText $iif($regml(3), $v1, _NONE_)
            }

            ;; otherwise, store error and exit looping
            else {
              %Error = HTTP_ERROR Status line invalid: %HeadData
            }
          }

          ;; If the status line has been received, assume the current line is a header
          ;;   Validate the header's format, get an index to store the header under, store it, and output debug message
          elseif ($regex(header, %HeadData, ^(\S+): (.*)$)) {
            %Index = $calc($hfind($sockname, HTTPRESP_HEADER?*_*, 0, w) + 1)
            hadd $sockname $+(HTTPRESP_HEADER, %Index, _, $regml(header, 1)) $regml(header, 2)
            _WebSocket.Debug -i %Name $+ >HEADER~Header Received: $regml(header, 1) $+ : $regml(header, 2)
          }

          ;; If the current line isn't a correctly formatted error
          ;;   store the error and exit looping
          else {
            %Error = HTTP_ERROR Response contained an invalid header
          }
        }

        ;; If the HTTP version is not HTTP/1.1
        elseif ($hget($sockname, HTTPRESP_HttpVersion) !== 1.1) {
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
          bset -c &_WebSocket_SecWebSockAccept 1 $regsubex($sha1($hget($sockname, HTTPREQ_SecWebSocketKey) $+ 258EAFA5-E914-47DA-95CA-C5AB0DC85B11), /(..)/g, $base(\t, 16, 10) $+ $chr(32))
          noop $encode(&_WebSocket_SecWebSockAccept, mb)

          ;; ERROR - The response security key does not match the digest of the sent key
          if (%SecAccept !== $bvar(&_WebSocket_SecWebSockAccept, 1-).text) {
            %Error = HTTP_ERROR Sec-WebSocket-Accept header value does not match digested key
          }

          ;; SUCCESS! - Head received and contains approiate data
          ;;   Stop timeout timer, update state variable, output debug message, raise event
          else {
            $+(.timer, _WebSocket_Timeout_, %Name) off
            hadd $sockname SOCK_STATE 4
            _WebSocket.Debug -s %Name $+ >HANDSHAKE~Handshake complete; ready to send and recieve frames!
            .signal -n WebSocket_READY_ $+ %Name
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

    ;; cleanup before further processing
    bunset &_WebSocket_ReadBuffer &_WebSocket_RecvData

    ;; read all data in socket buffer and append the to any remaining data
    ;; from a previous read
    sockread $sock($sockname).rq &_WebSocket_RecvData
    if ($hget($sockname, WSFRAME_PENDING, &_WebSocket_ReadBuffer)) {
      bcopy -c &_WebSocket_ReadBuffer $calc($bvar(&_WebSocket_ReadBuffer, 0) + 1) &_WebSocket_RecvData 1 -1
    }
    else {
      bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_RecvData 1 -1
    }
    bunset &_WebSocket_RecvData

    ;; Begin looping over the buffer data in an attempt to seperate frames
    while ($bvar(&_WebSocket_ReadBuffer, 0) >= 2) {

      ;; cleanup before processing each frame
      hdel $sockname WSFRAME_DATA
      hdel $sockname WSFRAME_TYPE
      bunset &_WebSocket_FrameData

      %HeadSize  = 2
      %Header    = $bvar(&_WebSocket_ReadBuffer, 1, 1)
      %IsFinal   = $isbit(%Header, 8)
      %RSVBits   = $calc($isbit(%Header, 7) *4 + $isbit(%Header, 6) *2 + $isbit(%Header, 5))
      %IsControl = $isbit(%header, 4)
      %FrameType = $calc(%Header % 128 % 64 % 32 % 16)
      %DataSize  = $bvar(&_WebSocket_ReadBuffer, 2, 1)


      ;; Error: RSV bits in use
      if (%RSVBits) {
        %Error = FRAME_ERROR Extension reserved bits used without extension negociation
      }

      ;; Error: fragmented control frame
      elseif (%IsControl && !%IsFinal) {
        %Error = FRAME_ERROR Fragmented control frame received
      }

      ;; Unknown Control frame
      elseif (%IsControl && %FrameType !isnum 8-10) {
        %Error = FRAME_ERROR Unkown CONTROL frame received( $+ %FrameType $+ )
      }

      ;; Error: Unknown data frame
      elseif (!%IsControl && %FrameType !isnum 0-2) {
        %Error = FRAME_ERROR Unkown DATA frame received( %FrameType )
      }

      ;; Error: Masked data from server
      elseif ($isbit(%DataSize, 8)) {
        %Error = FRAME_ERROR Masked frame received
      }

      ;; Error: Control frame larger than 127 bytes
      elseif (%IsControl && %DataSize > 125) {
        %Error = FRAME_ERROR Control frame received larger than 127 bytes
      }

      ;; Error: Current frame not part of previously received fragment
      elseif (!%IsControl && $hget($sockname, WSFRAME_FRAGMSG) && %FrameType !== 0) {
        %Error = FRAME_ERROR Frame-Type specified with subsequent frame fragment
      }

      ;; Error: current frame indicates continuation with no preceeding fragment frame received
      elseif (!$hget($sockname, WSFRAME_FRAGMSG) && %FrameType == 0) {
        %Error = FRAME_ERROR Continuation frame received with no preceeding fragmented frame
      }

      ;; Initial checks passed
      else {

        ;; If payload length is 126; the payload is a 16bit integer.
        if (%DataSize == 126) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 4) {
            break
          }
          elseif ($bvar(&_WebSocket_ReadBuffer, 3).nword < 126) {
            %Error = FRAME_ERROR Excessive payload size integer recieved from server
            break
          }
          %DataSize = $v1
          %HeadSize = 4
        }

        ;; If the payload is equal to 127 the payload is a 64bit integer
        elseif (%DataSize == 127) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 10) {
            break
          }
          elseif ($bvar(&bvar_WebSocket_ReadBuffer, 7).nlong < 4294967296) {
            %Error = FRAME_ERROR Excessive payload size integer recieved from server
            break
          }
          elseif ($bvar(&_WebSocket_ReadBuffer, 3).nlong) {
            %Error = FRAME_ERROR Frame would exceed a 4gb limit
            break
          }
          %DataSize = $bvar(&_WebSocket_ReadBuffer, 7).nlong
          %HeadSize = 10
        }

        ;; Check to make sure the entire frame as been received
        if ($calc(%HeadSize + %DataSize) < $bvar(&_WebSocket_ReadBuffer, 0)) {
          break
        }


        ;; If the frame is a continuation, retrieve previously received
        ;; fragment.
        if (%FrameType === 0 && $hget($sockname, WSFRAME_FRAGMSG)) {
          %FrameType = $hget($sockname, WSFRAME_FRAGMSG_Type)
          noop $hget($sockname, WSFRAME_FRAGMSG, &_WebSocket_FrameData)
          hdel $sockname WSFRAME_FRAGMSG_Type
          hdel $sockname WSFRAME_FRAGMSG_Data
          hdel $sockname WSFRAME_FRAGMSG
        }

        ;; Copy the frame's data from the ReadBuffer to the FrameData
        ;; buffer the remove the data from the ReadBuffer
        if (%DataSize) {
          bcopy -c &_WebSocket_FrameData $calc($bvar(&_WebSocket_FrameData,0) + 1) &_WebSocket_ReadBuffer $calc(%HeadSize + 1) %Datasize
        }
        if ($calc(%HeadSize + %DataSize) == $bvar(&_WebSocket_ReadBuffer, 0)) {
          bunset &_WebSocket_ReadBuffer
        }
        else {
          bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_ReadBuffer $calc(%HeadSize + %DataSize + 1) -1
        }

        ;; non-final fragment
        if (!%IsFinal) {
          hadd $sockname WSFRAME_FRAGMSG $true
          hadd $sockname WSFRAME_FRAGMSG_Type %FrameType
          hadd -b $sockname WSFRAME_FRAGMSG_Data &_WebSocket_FrameData
        }

        ;; full message recieved
        else {

          ;; store the frame type and data
          hadd $sockname WSFRAME_TYPE %FrameType
          if ($bvar(&_WebSocket_FrameData, 0)) {
            hadd -b $sockname WSFRAME_DATA &_WebSocket_FrameData
          }
          else {
            hdel $sockname WSFRAME_DATA
          }

          ;; TEXT or BINARY frame
          ;;   Output debug message and raise data event
          if (%FrameType isnum 1-2) {
            _WebSocket.Debug -i %Name $+ >FRAME~ $+ $iif(%FrameType == 1, TEXT, BINARY) frame recieved
            .signal -n WebSocket_DATA_ $+ %Name
          }

          ;; PING frame
          ;;   Output debug message, response with pong, raise data event
          elseif (%FrameType == 9) {
            _WebSocket.Debug -i %Name $+ >FRAME~PING frame recieved
            WebSockWrite -P %Name &_WebSocket_FrameData
            .signal -n WebSocket_DATA_ $+ %Name
          }

          ;; PONG frame
          ;;   Output debug message and raise data event
          elseif (%FrameType == 10) {
            _WebSocket.Debug -i %Name $+ >FRAME~PONG frame recieved
            .signal -n WebSocket_DATA_ $+ %Name
          }

          ;; CLOSE Frame - Data after frame
          elseif ($bvar(&_WebSocket_ReadBuffer, 0)) {
            %Error = FRAME_ERROR Data recieved after a CLOSE frame has been recieved.
            break
          }

          ;; CLOSE frame - Server Requested
          elseif (!$hget($sockname, CLOSE_PENDING)) {
            _WebSocket.Debug -i %Name $+ >FRAME~CLOSE frame received.
            hadd $sockname SOCK_STATE 5
            .signal -n WebSocket_CLOSING_ $+ %Name %Name
            WebSockClose %Name
          }

          ;; CLOSE Frame - Client requested & server responded
          else {
            _WebSocket.Debug -i2 %Name $+ >FRAME:CLOSE~CLOSE frame reply received; closing connection.
            .signal -n WebSocket_CLOSE_ $+ %Name
            _WebSocket.Cleanup $sockname
            return
          }
        }
      }
    }

    ;; If no errors occured, update the buffer
    if (!%Error) {
      if ($bvar(&_WebSocket_ReadBuffer, 0)) {
        hadd -b $sockname WSFRAME_PENDING &_WebSocket_ReadBuffer
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
  %Error = $iif($error, MIRC_ERROR $v1, %Error)
  if (%Error) {
    reseterror
    _WebSocket.Debug -e SockRead> $+ %Name $+ ~ $+ %Error
    _WebSocket.RaiseError %Name %Error
  }
}