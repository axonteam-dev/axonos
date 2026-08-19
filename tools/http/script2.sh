export PATH=/opt/bin:/opt/sbin:$PATH
cat >> /opt/var/pgsql/data/postgresql.conf << 'EOF'
listen_addresses = '*'
unix_socket_directories = '/tmp'
huge_pages = off
shared_buffers = 16MB
max_connections = 20
dynamic_shared_memory_type = mmap
EOF
chown postgres /opt/var/pgsql/data/postgresql.conf
rm -f /opt/var/pgsql/data/postmaster.pid
su postgres -c '/opt/bin/postgres -D /opt/var/pgsql/data'
