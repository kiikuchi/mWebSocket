# mWebSocket
mWebSocket aims to implement the client portion of the [WebSocket Standard](https://tools.ietf.org/html/rfc6455) in mSL for mIRC and AdiIRC. It is not, however, a fully featured HTTP client and as such will not follow HTTP redirects or process non-websocket related responses.  
&nbsp;  

Due to this script being in early developement expect a flux of changes along with the documentation not being 100% up to date.

&nbsp;  
If you appreciate the work done, consider donating via paypal: froggiedafrog@aim.com  

&nbsp;  
&nbsp;  

Requirements
------------
mIRC v7.4x or AdiIRC v2.2  

&nbsp;  
&nbsp;  

Installing
----------
1. Download `mWebSocket-vx.x.xxxx-stable.mrc` from the root directly or `mWebSocket-vx.x.xxxx-yyyy.mrc` from the /builds/ directory  
2. In mIRC/AdiIRC, enter the following command in an editbox: `//load -rs $$sfile($mircdir, Load, Open)`  
3. Navigate to and select the downloaded file  
4. Click "Open"  

&nbsp;  
&nbsp;  

Commands
--------

#### `/WebSockOpen name uri [timeout]`
> Creates a WebSocket handler.  

**Switches**
> None  

&nbsp;  
**Parameters**
> **`name`** - required  
> The name to reference the handler by. Must be not be an interger or start with `-`  
>  
> **`uri`** - required  
> The uri to connect to. Use `wss://` as the uri scheme for an SSL connection  
>  
> **`timeout`** - optional  
> The time, in seconds, to wait for the connection to be established before timing out the connection  

&nbsp;  
&nbsp;   

#### `/WebSockWrite -[cpPbt]+t name text|&bvar`
> Sends the specified frame through the WebSocket.  
> Can only be used after the HANDSHAKE has completed.  

**Switches**
> `-c`  
> The data should be sent as a CLOSE frame  
>  
> `-p`  
> The data should be sent as a PING frame  
>  
> `-P`  
> The data should be sent as a PONG frame  
>  
> `-b`  
> The data should be sent as a BINARY frame  
>  
> `-t`  
> The data should be sent as a TEXT frame (default)  
>  
> `+t`  
> The passed data is to be treated as plain-text

&nbsp;  
**Parameters**
> `name` - required  
> The WebSocket name.  
>  
> `text|&bvar` - required  
> The data to be included with the frame  

&nbsp;  
&nbsp;  

#### `/WebSockHeader header value`
> Stores the specified header to be used with the HTTP request.  
> Can only be used from the `INIT` event

**Switches**  
> None  

&nbsp;  
**Parameters**
> `header` - required  
> The header name to set  
>
> `value` - required  
> The value for the header  

&nbsp;  
&nbsp;  

#### `/WebSockClose -f name`
> Sends a CLOSE control-frame to the server  

**Switches**  
> `-f`  
> If specified the socket will be immediately closed  

&nbsp;  
**Parameters**  
> `name` - required  
> The WebSocket to close  

&nbsp;  
&nbsp;  

Identifiers
-------------

#### `$WebSock`  
> If used from within a WebSocket event, the WebSocket name is returned

&nbsp;  
&nbsp;  

#### `$WebSock(name)`  
> Returns the websocket name if it exists  

**Parameters**  
> `name` - required  
> The name of the WebSocket instance  

**Properties**  
> `State`  
> Returns the current websocket state  
>
> `StateText`  
> Returns the text equivulant of the websocket state  
>  
> `Ssl`  
> Returns `$true` if the connection is Ssl  
>  
> `Host`  
> Returns the host for the connection  
>  
> `Port`  
> Returns the port connected to  
>  
> `Uri`  
> Returns the URI used to connect to  
>  
> `HttpVersion`  
> Returns the HTTP version of the connection  
> Only applicatable after the HTTP response has been received  
>  
> `StatusCode`  
> Returns the HTTP statuscode returned by the server  
> Only applicatable after the HTTP response has been received  
>  
> `StatusText`  
> Returns the HTTP Status Text returned by the server  
> Only applicatable after the HTTP response has been received  

&nbsp;  
&nbsp;  

#### `$WebSock(name, [header,] n).HttpHeader`  
> Returns the specified header.  
> Only applictable after the HTTP response has been received  

**Parameters**
> `name` - Required  
> The name of the WebSocket instance  
>  
> `header` - Optional  
> The name of the header to look up  
> If specified, the nth header of the specified name is returned  
> If `n` is `0` the total number of matching headers is returned  
>  
> `n` - Required  
> Returns the nth header.  
> if a `[header]` name is not specified, the nth header name is returned  
> if `0` the total number of headers is returned  

&nbsp;  
&nbsp;  

#### `$WebSockType`  
> Returns the frame-type recieved  
> Only applicable from within the `CLOSING` and `DATA` events  

&nbsp;  
&nbsp;  


#### `$WebSockTypeText`  
> Returns the frame-type recieved as text (`CLOSE`, `PING`, `TEXT`, etc)
> Only applicable from within the `CLOSING` and `DATA` events  

&nbsp;  
&nbsp;  

#### `$WebSockText`  
> Returns the data recieved as text.  
> Only applicable from within the `CLOSING` and `DATA` events  

&nbsp;  
&nbsp;  

#### `$WebSockData(&bvar)`  
> Fills the specified binary variable with the received data  
> Only applicable from within the `CLOSING` and `DATA` events  

**Parameters**  
> `&bvar` - Required  
> An empty bvar to be filled with the read data  

&nbsp;  
&nbsp;  

#### `$WebSockErr`  
> Returns the WebSocket error  
> Only applicatable from within the `ERROR` event  

&nbsp;  
&nbsp;  

#### `$WebSockErrMsg`
> Returns the WebSocket error message  
> Only applicatable from within the `ERROR` event

&nbsp;  
&nbsp;  

Events
--------

#### Format  
> Al events are raised as a signal event formated as:  
> `WebSocket_[EVENT]_[name]`  
>
> `[EVENT]`
> The event name
>
> `[name]`  
> The websocket name from which the event originated

&nbsp;  
&nbsp;  

#### Event: `INIT`
> Raised when the socket connection has been established.  
>
> `$WebSock` can be used to retrieve the WebSock name  
> `/WebSockHeader` can be used from within this event to set request headers  
  
&nbsp;  
&nbsp; 
  
#### Event: `REQSEND`
> Raise when the HTTP request has been sent and a server response is pending
>
> `$WebSock` can be used to retrieve the WebSock name  

&nbsp;  
&nbsp; 

#### Event: `READY`
> Raised when the HTTP handshake has successfully completed and the WebSocket is ready to send/recieve data  
>
> `$WebSock` can be used to retrieve the WebSock name  

&nbsp;  
&nbsp; 

#### Event: `DATA`
> Raised when a DATA, PING or PONG frame has been recieved.
>
> `$WebSock` can be used to retrieve the WebSock name  
> `$WebSockType`, `$WebSockTypeText`, `$WebSockText` and `$WebSockData` can be used to reference the received data  
>
> The script will automatically respond to WebSocket PING frames

&nbsp;  
&nbsp;

#### Event: `CLOSING`
> Raised when a CLOSE frame has been recieved
>
> `$WebSock` can be used to retrieve the WebSock name  
> `$WebSockType`, `$WebSockTypeText`, `$WebSockText` and `$WebSockData` can be used to reference the recieved data 

&nbsp;  
&nbsp; 

#### Event: `CLOSED`
> Raised when the remote host has closed the connection.  
> The websocket will be destroyed after this event.
>
> A new websocket can not be created from this event reusing the name.

&nbsp;  
&nbsp; 

#### Event: `ERROR`
> Raised when an error occured durring socket communications.  
> The websocket will be destroyed after this event.
>
> `$WebSockErr` and `$WebSockErrMsg` can be used to access information about the error
>
> A new websocket can not be created from this event reusing the name.

&nbsp;  
&nbsp; 

#### Event: `FINISHED`
> Raised after a websocket has been destroyed
>
> A new websocket **CAN** be created from this event reusing the name  

&nbsp;  
&nbsp;  

Special Thanks
--------------
> ACPixel: Giving me the idea  
> Membear: Giving me extensive examples to help me understand the protocol  
> Ouims:   Various general help  
