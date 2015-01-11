Websockify port for Nginx
=========================

Embed the [Websockify](https://github.com/kanaka/websockify/) into Nginx

some codes are borrowed from [Websockify C implementation](https://github.com/kanaka/websockify/tree/master/other)


Installation
------------
    

    git clone https://github.com/tg123/websockify-nginx-module.git
    
    cd path/to/nginx_source
    
    ./configure --add-module=/path/to/websockify-nginx-module/
    
    make
    make install


Uasge
-----

  in your `nginx.conf`
  
    location /websockify {
        websockify_pass yourvncip:port
    }

    

  1. visit <http://kanaka.github.io/noVNC/noVNC/vnc.html> in your browser, 
  1. Host is your `nginx server`'s ip
  1. port is your `nginx server`'s listening port
  1. Click connect

Options
-------

  * `websockify_buffer_size`:  Default: `65535 + 4 (websocket max frame size + header)`

    The buffer size used to store the encode/decode data.
    each websockify connection will cost `websockify_buffer_size` * 2 ( 1 upstream + 1 downstream ) addational memory


  * `websockify_read_timeout`: Default `60s`
    
    [proxy_read_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout) of websockify upstream


  * `websockify_connect_timeout`: Default `60s`
    
    [proxy_connect_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout) of websockify upstream


  * `websockify_send_timeout`: Default `60s`
    
    [proxy_send_timeout](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_send_timeout) of websockify upstream

    
Nginx Compatibility
-------------------

 * 1.5.x (Tested on 1.5.9)
 * 1.4.x (Tested on 1.4.4)
