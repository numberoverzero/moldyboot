#!/usr/bin/env bash
# TODO support list of domains
# TODO this should include api.moldyboot.com and console.moldyboot.com
DOMAIN=moldyboot.com

# Install acme.sh
curl https://get.acme.sh | sh

if [-z "$CF_Key"]; then
    echo "CF_Key is not set."
    echo "Get your Global API Key for CloudFlare from"
    echo "https://www.cloudflare.com/a/account/my-account"
    echo "And enter it here:"
    read CF_Key
fi

if [-z "$CF_Email"]; then
    echo "CF_Email is not set."
    echo "Get your CloudFlare email address from"
    echo "https://www.cloudflare.com/a/account/my-account"
    echo "And enter it here:"
    read CF_Email
fi
echo "Writing credentials to .acme.sh/account.conf"
cat <<EOF >> .acme.sh/account.conf
CF_Key='$CF_Key'
CF_Email='$CF_Email'
USER_PATH='$PATH'
EOF

CERTS=/etc/nginx/certs/$DOMAIN
ACME=/home/deploy/.acme.sh/acme.sh

# Issue certs
echo "Issuing certs"
$ACME --issue --dns dns_cf -d $DOMAIN

# Install certs to Nginx
echo "Installing certs"
mkdir -p $CERTS
$ACME --installcert -d $DOMAIN --certpath $CERTS/cert.pem --keypath $CERTS/key.pem --fullchainpath $CERTS/fullchain.pem --reloadcmd "service nginx restart"

# Let deploy user restart/reload nginx without a password
cat <<EOF > /etc/sudoers.d/nginx-overrides
# Nginx Commands
Cmnd_Alias NGINX_RESTART = /usr/sbin/service nginx restart
Cmnd_Alias NGINX_RELOAD  = /usr/sbin/service nginx reload
Cmnd_Alias ACME_CRON     = /home/deploy/.acme.sh/acme.sh

# No-Password Commands
deploy ALL=NOPASSWD: NGINX_RESTART, NGINX_RELOAD, ACME_CRON
EOF
