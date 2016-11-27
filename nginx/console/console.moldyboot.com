server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name console.moldyboot.com;

    access_log /var/log/nginx/console/access.log;
    error_log  /var/log/nginx/console/error.log;

    root /services/console/static;
    # remove trailing slash
    rewrite ^/(.*)/$ /$1 permanent;
    # remove trailing .html
    rewrite ^/(.*)\.html$ /$1 permanent;

    location / {
        try_files $uri $uri.html =404 last;
    }
}
