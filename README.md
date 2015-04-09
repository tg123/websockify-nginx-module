# Websockify port for Nginx

Embed the [Websockify](https://github.com/kanaka/websockify/) into Nginx

## Installation


    git clone https://github.com/tg123/websockify-nginx-module.git
    
    cd path/to/nginx_source
    
    ./configure --add-module=/path/to/websockify-nginx-module/
    
    make
    make install


## Uasge

### Single noVNC websockify proxy

  in your `nginx.conf`

```
location /websockify {
    websockify_pass yourvncip:port
}
```
    

  1. visit <http://kanaka.github.io/noVNC/noVNC/vnc.html> in your browser, 
  1. Host is your `nginx server`'s ip
  1. port is your `nginx server`'s listening port
  1. Click connect


### Dynamic vnc upstream with help of [ngx-lua](https://github.com/chaoslawful/lua-nginx-module)

an example script read ip and port from url params and verify them by md5 

__SECURITY VULNERABILITY WARNING__ 

> this is only an exmaple for you to understand how to work together with ngx-lua
> do NOT use this script in production.

> anyone who know your private key can connect any machine behind your nginx proxy,
> you should restrict target ip and port in a whitelist.


  in your `nginx.conf`

```
location /websockify {

    set $vnc_addr '';
    access_by_lua '

        -- your private key here
        local key = "CHANGE_ME_!!!!"
        
        -- read from url params
        local args = ngx.req.get_uri_args()
        local ip = args["ip"] or "127.0.0.1"
        local port = args["port"] or  "5900"
        local sign = args["sign"]
        local t = tonumber(args["t"]) or 0
        local elapse = ngx.time() - t

        -- make sure the signature are generated within 30 seconds
        if elapse > 30 or elapse < 0  then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        local addr = ip .. ":" .. port

        -- verify the signature
        if ngx.md5(key .. t .. addr .. key) ~= sign then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        ngx.var.vnc_addr = addr
    ';

    websockify_pass $vnc_addr;
}
```

use ajax call to `vnc_url.php` to retrieve the websockify url, then let noVNC connect to it.

```
<?php

// query you vnc ip and port from somewhere, e.g. mysql.
//

// query result
$addr = '127.0.0.1';
$port = 5900;

// same as private key in nginx.conf
$key = "CHANGE_ME_!!!!";

$t = time();

echo '/websockify/?' . http_build_query(array(
    't' =>  $t,
    'sign' => md5($key . $t . "$addr:$port" . $key),
    'ip' => $addr,
    'port' => $port,
));
```



# Directives

  * `websockify_buffer_size`:  Default: `65543 = 65535 + 4 + 4 (websocket max frame size + header + mask)`

    The buffer size used to store the encode/decode data.
    each websockify connection will cost `websockify_buffer_size` * 2 ( 1 upstream + 1 downstream ) addational memory


  * `websockify_read_timeout`: Default `60s`
    
    [proxy_read_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout) of websockify upstream


  * `websockify_connect_timeout`: Default `60s`
    
    [proxy_connect_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout) of websockify upstream


  * `websockify_send_timeout`: Default `60s`
    
    [proxy_send_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_send_timeout) of websockify upstream

    
# Nginx Compatibility

 * v0.02 - v0.0.3
    * 1.7.x (Tested on 1.7.9)
    * 1.6.x (Tested on 1.6.2)

 * v0.0.1

     * 1.5.x (Tested on 1.5.9)
     * 1.4.x (Tested on 1.4.4)
