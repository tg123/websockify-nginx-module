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

  There are three options you can use to adjust them for different situation:

  * `websockify_buffer_size`  :  Default: `32768` 
    The buffer size used to store the encode/decode data.


Nginx Compatibility
-------------------

 * 1.5.x (Tested on 1.5.9)
 * 1.4.x (Tested on 1.4.4)
