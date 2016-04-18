# ddnsclient6
A dyndns-compatible client for dynamic IPv6 addresses

ddnsclient listens via netstat for changes in the IPv6 address and performs a request to a dyndns-compatible server for every address which is not filtered out in the function filter_ip()

Usage:
  ddnsclient
    -d    -- Start in daemon-mode (logs into /var/log/ddnsclient)
    -v    -- verbose output

Known issues / TODO:
  Make config for upstart etc
  Reduce non-verbose logging (and log to syslog?)
  Daemon-mode does not yet support pid-files
  
