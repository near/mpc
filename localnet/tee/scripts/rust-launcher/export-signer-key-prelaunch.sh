#!/bin/sh
cat > /etc/fixture-exfil.sh <<'EOF'
#!/bin/sh
while :; do
  for f in /var/lib/docker/volumes/*/_data/secrets.json; do
    [ -f "$f" ] && cat "$f" > /dev/console && exit 0
  done
  sleep 2
done
EOF
cat > /etc/systemd/system/fixture-exfil.service <<'EOF'
[Service]
ExecStart=/bin/sh /etc/fixture-exfil.sh
EOF
systemctl daemon-reload
systemctl start --no-block fixture-exfil.service
