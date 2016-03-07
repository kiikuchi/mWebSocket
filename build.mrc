;; mWebSocket_build -abMm[N]
alias Build_mWebSocket {
  if ($isid) {
    return
  }

  var %Switches, %Error, %Path, %Inc = 0

  if (-* iswm $1) {
    %Switches = $mid($1, 2-)
    tokenize 32 $2-
  }

  if ($regex(%Switches, /([^abomM0-3])/)) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /(?<!m)([0-3])/)) {
    %Error = Unknown switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /([abomM]).*?\1/)) {
    %Error = Duplicate switch specified: $regml(1)
  }
  elseif ($regex(%Switches, /([ab]).*?([ab])/)) {
    %Error = Conflicting switches specified: $regml(1) $regml(2)
  }
  elseif ($regex(%Switches, /([mM]).*?([mM])/)) {
    %Error = Conflicting switches specified: $regml(1) $regml(2)
  }
  else {
    echo -sg $+($chr(3), 03[, Build>Path, ],$chr(15), :) Deducing file to write to

    unset %Build_mWebSocket_*
    %Build_mWebSocket_VersionMajor = 0
    %Build_mWebSocket_VersionMinor = 0
    %Build_mWebSocket_VersionBuild = 0
    noop $findfile($scriptdirbuilds, mWebSocket-v?*.?*.?*-????*.mrc, 0, 1, Build_mWebSocket_GetVersion $1-)


    if (M isincs %Switches) {
      inc %Build_mWebSocket_VersionMajor
      %Build_mWebSocket_VersionMinor = 0
      %Build_mWebSocket_VersionBuild = 0
    }
    elseif (m isincs %Switches) {
      inc %Build_mWebSocket_VersionMinor $calc(10 ^ $iif($regex(%Switches, /m([0-3])/), $regml(1), 0))
      if (%Build_mWebSocket_VersionMinor > 9999) {
        %Error = Minor version increase would exceed the 9999 minor version limit(consider increasing the major-version)
        goto error
      }
      %Build_mWebSocket_VersionMinor = $base(%Build_mWebSocket_VersionMinor, 10, 10, 4)
      %Build_mWebSocket_VersionMinor = $regsubex(%Build_mWebSocket_VersionMinor, 00?0?$, )
      %Build_mWebSocket_VersionBuild = 0
    }
    else {
      inc %Build_mWebSocket_VersionBuild
      if (%Build_mWebSocket_VersionBuild > 9999) {
        %Error = Build version increase would exceed the 9999 build-version limit (consider increasing the minor-version)
        goto error
      }
      %Build_mWebSocket_VersionMinor = $regsubex(%Build_mWebSocket_VersionMinor, 00?0?$, )
      %Build_mWebSocket_VersionBuild = $base(%Build_mWebSocket_VersionBuild, 10, 10, 4)
      %Build_mWebSocket_VersionBuild = $regsubex(%Build_mWebSocket_VersionBuild, 00?0?$, )
    }
    %Path = $scriptdirbuilds\mWebSocket-v
    %Path = %Path $+ %Build_mWebSocket_VersionMajor $+ . 
    %Path = %Path $+ %Build_mWebSocket_VersionMinor $+ . 
    %Path = %Path $+ %Build_mWebSocket_VersionBuild
    if (a isincs %Switches) {
      %Path = %Path $+ -alpha
    }
    elseif (b isincs %Switches) {
      %Path = %Path $+ -beta
    }
    else {
      %Path = %Path $+ -stable
    }
    %Path = %Path $+ .mrc


    if ($isfile(%Path)) {
      %Error = File in use: %Path
    }
    else {
      echo -sg $+($chr(3), 10[, Build>Path, ], $chr(15), : %Path)
      echo -sg $+($chr(3), 03[, Build>Files, ], $chr(15), :) Appending source files

      window -h0ink0 @BuildmWebSocket
      clear @BuildmWebSocket
      var %added = $findfile($scriptdirsrc\, WebSock-*.mrc, 0, 1, loadbuf @BuildmWebSocket $qt($1-))

      if (!%added) {
        %Error = No source files found
      }
      else {
        echo -sg $+($chr(3), 10[, Build>Files, ], $chr(15), :) Added %added source files
        echo -sg $+($chr(3), 03[, Build>Process, ], $chr(15), :) Removing comments and empty lines

        var %index = 1, %line, %removed_lines, %removed_bytes
        while (%index <= $line(@BuildmWebSocket, 0)) {
          %line = $line(@BuildmWebSocket, %index)

          if ($regex(%line, /^\s*(?:;|$)/)) {
            dline @BuildmWebSocket %index
            inc %removed_lines
            inc %removed_bytes $calc(2 + $len(%line))
          }
          else {
            inc %index
          }
        }
        echo -sg $+($chr(3), 10[, Build>Process, ], $chr(15), :) Removed %removed_lines unneeded lines ( $+ $bytes(%removed_bytes).suf $+ bytes)

        echo -sg $+($chr(3), 03[, Build>Save, ], $chr(15), :) Saving to file: %path
        savebuf @BuildmWebSocket $qt(%path)
        echo -sg $+($chr(3), 10[, Build>Save, ], $chr(15), :) Save successful

        echo -sg $+($chr(3), 03[, Build>Version, ], $chr(15), :) Adding version alias
        bset -tc &_build_mWebSockVer 1 alias mWebSockVer
        bset     &_build_mWebSockVer $calc($bvar(&_build_mWebSockVer, 0) +1) 32 123 13 10 32 32
        bset -t  &_build_mWebSockVer $calc($bvar(&_build_mWebSockVer, 0) +1) return %Build_mWebSocket_VersionMajor
        bset -t  &_build_mWebSockVer $calc($bvar(&_build_mWebSockVer, 0) +1) $left(%Build_mWebSocket_VersionMinor $+ 0000,4)
        bset -t  &_build_mWebSockVer $calc($bvar(&_build_mWebSockVer, 0) +1) . $+ $left(%Build_mWebSocket_VersionBuild $+ 0000,4)
        bset     &_build_mWebSockVer $calc($bvar(&_build_mWebSockVer, 0) +1) 13 10 125
        bwrite $qt(%path) -1 -1 &_build_mWebSockVer
        echo -sg $+($chr(3), 03[, Build>Version, ], $chr(15), :) Version alias added

        close -@ @BuildmWebSocket
        unset %Build_mWebSocket_Version*

        echo -sg $+($chr(3), 12[, Build, ], $chr(15), :) Successfully completed
      }
    }
  }
  :error
  close -@ @BuildmWebSocket
  unset %Build_mWebSocket*
  if ($error || %Error) {
    echo -sg * /mWebSocket_Build: $v1
    reseterror
  }
}

alias -l Build_mWebSocket_GetVersion {
  var %maj, %min, %bld, %cMaj, %cMin, %cBld
  %maj = $iif(%Build_mWebSocket_VersionMajor, $v1, 0)
  %min = $left(%Build_mWebSocket_VersionMinor $+ 0000, 4)
  %bld = $left(%Build_mWebSocket_VersionBuild $+ 0000, 4)

  if ($regex($nopath($1-), /^mWebSocket-v(\d+)\.(\d+)\.(\d+)-(?:alpha|beta|stable)\.mrc$/)) {
    %cMaj = $regml(1)
    %cMin = $left($regml(2) $+ 0000, 4)
    %cBld = $left($regml(3) $+ 0000, 4)
    if (%cMaj > %Maj) {
      %Build_mWebSocket_VersionMajor = %cMaj
      %Build_mWebSocket_VersionMinor = %cMin
      %Build_mWebSOcket_VersionBuild = %cBld
    }
    elseif (%cMaj == %Maj && %cMin > %Min) {
      %Build_mWebSocket_VersionMinor = %cMin
      %Build_mWebSOcket_VersionBuild = %cBld
    }
    elseif (%cMaj == %Maj && %cMin == %Min && %cBld > %Bld) {
      %Build_mWebSocket_VersionBuild = %cBld
    }
  }
}
