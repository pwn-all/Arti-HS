#Block incomming UPD traffic. Tor supports only TCP.
nft add rule inet filter input udp drop

#Rate limit incommign TCP
nft add rule inet filter input tcp flags syn \
  limit rate 100/second burst 200 packets accept
nft add rule inet filter input tcp flags syn drop

# SYN Cookies
sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.ipv4.tcp_synack_retries=3
sysctl -p


echo '''[Unit]
Description=Arti Hidden Service
After=network.target

[Service]
ExecStart=/usr/local/bin/myapp. # path to application
User=hsapp
Restart=on-failure

# --- CPU limits ---
CPUQuota=50%          # max 50% of 1 core; 200% = 2 cores, etc.

# --- RAM limits ---
MemoryMax=1G          # hard cap (OOM-kill if exceeded)
MemoryHigh=800M       # soft pressure threshold (optional but nice)

# --- Extra safety (optional) ---
TasksMax=300
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target''' > /etc/systemd/system/hs-daemon.service

systemctl daemon-reload
systemctl enable --now hs-daemon.service
systemctl status hs-daemon.service
