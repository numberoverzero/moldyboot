server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.moldyboot.com;

    access_log /var/log/nginx/api/access.log;
    error_log  /var/log/nginx/api/error.log;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/services/api/api.sock;
    }
}
