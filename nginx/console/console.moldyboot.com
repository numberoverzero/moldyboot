server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name console.moldyboot.com;

    access_log /var/log/nginx/console/access.log;
    error_log  /var/log/nginx/console/error.log;

    # only respond to CloudFlare's cert
    ssl_client_certificate /etc/nginx/ssl/origin-pull-ca.pem;
    ssl_verify_client on;

    # certs sent to the client in SERVER HELLO are concatenated in ssl_certificate
    ssl_certificate /etc/nginx/certs/moldyboot.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/moldyboot.com/key.pem;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Diffie-Hellman parameter for DHE ciphersuites, recommended 4096 bits
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    # modern configuration. tweak to your needs.
    ssl_protocols TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
    ssl_prefer_server_ciphers on;

    # HSTS (ngx_http_headers_module is required) (15768000 seconds = 6 months)
    add_header Strict-Transport-Security max-age=15768000;

    # OCSP Stapling ---
    # fetch OCSP records from URL in ssl_certificate and cache them
    ssl_stapling on;
    ssl_stapling_verify on;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/services/console/console.sock;
    }

}

