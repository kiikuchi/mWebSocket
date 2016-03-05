on $*:SOCKREAD:/^_WebSocket_(?!\d+$)[^-?*][^?*]*$/:{
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
    bunset &_WebSocket_ReadBuffer &_WebSocket_RecvData

    ;; read all data in socket buffer
    sockread $sock($sockname).rq &_WebSocket_RecvData

    ;; append the newly read data to any remaining data from the previous read
    if ($hget($sockname, WSFRAME_PENDING, &_WebSocket_ReadBuffer)) {
      bcopy -c &_WebSocket_ReadBuffer $calc($bvar(&_WebSocket_ReadBuffer, 0) + 1) &_WebSocket_RecvData 1 -1
    }
    else {
      bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_RecvData 1 -1
    }
    bunset &_WebSocket_RecvData

    ;; cleanup before further processing
    hdel $sockname WSFRAME_DATA
    hdel $sockname WSFRAME_TYPE

    ;; Begin looping over the buffer data to seperate frames
    while ($bvar(&_WebSocket_ReadBuffer, 0) >= 2) {

      %HeadData = $bvar(&_WebSocket_ReadBuffer, 1, 1)
      %HeadSize = 2
      %FragSize = $bvar(&_WebSocket_ReadBuffer, 2, 1)

      ;; ERROR - CLOSE frame previously recieved; subsequent frames should not have been sent
      if ($hget($sockname, SOCK_STATE) == 5) {
        %Error = FRAME_ERROR Frame recieved after a CLOSE frame has been recieved.
      }

      ;; ERROR - Frame makes use of reserved bits (bit2, bit3, or bit4)
      elseif ($isbit(%HeadData, 5) || $isbit(%HeadData, 6) || $isbit(%HeadData, 7)) {
        %Error = FRAME_ERROR Frame used RSV bits
      }

      ;; ERROR - Frame head indicates a fragmented(bit1 = 0) control-frame(bits5-8 = 8,9,10)
      elseif (!$isbit(%HeadData, 8) && $calc(%HeadData % 128) isnum 8-10) {
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
      elseif (%FragSize == 127 && $bvar(&_WebSocket_ReadBuffer, 0) >= 6 && $bvar(&_WebSocket_ReadBuffer, 3).nlong !== 0) {
        %Error = FRAME_ERROR Data size would overflow an int32
      }
      else {

        ;; If the 2nd octlet is equal to 126, the fragment size is the following 2 octlets
        ;;   Make sure the entire frame head has been recieved, and update size variables
        if (%FragSize == 126) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 4) {
            break
          }
          %HeadSize = 4
          %FragSize = $bvar(&_WebSocket_ReadBuffer, 3, 2).nword
        }

        ;; If the 2nd octlet is equal to 127, the fragment size is the following 8 octlets
        ;;   Make sure the entire frame head has been recieved, and update size variables
        elseif (%DataSize == 127) {
          if ($bvar(&_WebSocket_ReadBuffer, 0) < 10) {
            break
          }
          %HeadSize = 10
          %FragSize = $bvar(&_WebSocket_ReadBuffer, 7).nlong
        }

        ;; Check to verify the entire frame has been read
        if ($bvar(&_WebSocket_ReadBuffer, 0) < $calc(%HeadSize + %FragSize)) {
          break
        }

        ;; Retrieve previously stored fragment data, then remove it from the hashtable
        bunset &_WebSocket_FrameData
        noop $hget($sockname, WSFRAME_Fragment, &_WebSocket_FrameData)
        hdel $sockname WSFRAME_Fragment
        hdel $sockname WSFRAME_FragmentType

        ;; Copy the newly read frame's data to any stored fragments parts, then remove the frame from the received buffer
        bcopy -c &_WebSocket_FrameData $calc($bvar(&_WebSocket_FrameData, 0) + 1) &_WebSocket_ReadBuffer $calc(%HeadSize + 1) %FragSize
        if ($calc(%HeadSize + %FragSize) == $bvar(&_WebSocket_ReadBuffer, 0)) {
          bunset &_WebSocket_ReadBuffer
        }
        else {
          bcopy -c &_WebSocket_ReadBuffer 1 &_WebSocket_ReadBuffer $calc($v1 +1) -1
        }

        ;; if there's frame data, store it for use with events
        if ($bvar(&_WebSocket_FrameData, 0)) {
          hadd -mb $sockname WSFRAME_DATA &_WebSocket_FrameData
        }

        ;; otherwise delete the frame data entry
        else {
          hdel $sockname WSFRAME_DATA
        }

        ;; Store the frame type
        hadd -m $sockname WSFRAME_TYPE $calc(%HeadData % 128)

        ;; Control-Frame (CLOSE)
        if (%HeadData == 136) {

          ;; ERROR - if there's data following the close frame, the connection is errorous
          if ($bvar(&_WebSocket_ReadBuffer, 0)) {
            %Error = FRAME_ERROR Data recieved after a CLOSE frame has been recieved.
          }

          ;; If the client sent a close frame and the server responded:
          ;;   Otherwise: output debug message, raise event, cleanup after the connection, exit processing
          elseif ($hget($sockname, CLOSE_PENDING)) {
            _WebSocket.Debug -i2 %Name $+ >FRAME:CLOSE~Close frame reply received; closing connection.
            .signal -n WebSocket_CLOSE_ $+ %Name
            _WebSocket.Cleanup $sockname
          }

          ;; The close frame is unsoliated:
          ;;   Output debug message, raise closing event, update sock state, and queue close frame
          else {
            _WebSocket.Debug -i %Name $+ >FRAME:CLOSE~Close frame received.
            .signal -n WebSocket_CLOSING_ $+ %Name %Name
            hadd $sockname SOCK_STATE 5
            WebSockClose %Name
          }
          break
        }

        ;; Control-Frame (PING)
        ;;   Output debug message, raise PING event, queue outgoing PONG frame
        elseif (%HeadData == 137) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Ping frame received.
          .signal -n WebSocket_PING_ $+ %Name
          WebSockWrite -P %Name &_WebSocket_FrameData
        }

        ;; Control-Frame (PONG)
        ;;  Output debug message and raise PONG event
        elseif (%HeadData == 138) {
          _WebSocket.Debug -i %Name $+ >FRAME:PING~Pong frame received.
          .signal -n WebSocket_PONG_ $+ %Name
        }

        ;; if the frame is not a final-fragment, store the data for the next frame read
        else if (!$isbit(%HeadData, 8)) {
          hadd -b $sockname WSFRAME_Fragment &_WebSocket_FrameData
          hadd $sockname  WSFRAME_FragmentType $calc(%HeadData % 128)
        }

        ;; Data-Frame: TEXT(129) or BINARY(130)
        elseif (%HeadData == 129 || %HeadData == 130) {
          _WebSocket.Debug -i %Name $+ >FRAME:Data~ $+ $iif(%HeadData == 129, Text, Binary) frame recieved
          .signal -n WebSocket_DATA_ $+ %Name
        }
      }

      ;; cleanup
      hdel $sockname WSFRAME_DATA
      hdel $sockname WSFRAME_TYPE

      ;; if an error occured, exit looping
      if (%Error) {
        break
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