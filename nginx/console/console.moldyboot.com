server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name console.moldyboot.com;

    access_log /var/log/nginx/console/access.log;
    error_log  /var/log/nginx/console/error.log;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/services/console/console.sock;
    }
}
