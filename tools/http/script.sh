export PATH=/opt/bin:/opt/sbin:$PATH
opkg update
opkg install pgsql-server pgsql-cli
mkdir -p /opt/var
adduser -D -u 5432 -h /opt/var/pgsql -s /bin/sh postgres
su postgres -c 'initdb -D /opt/var/pgsql/data --locale=C --encoding=UTF8'
