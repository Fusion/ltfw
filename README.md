# Light Touch Firewall

This incredibly simple program was written to deal with keeping ports closed.

The main use case is Kubernetes environments where iptables management interferes with an actual firewall.

Using `ltfw` you can specify which IP addresses are considered "too open" (default: `0.0.0.0`) as well as which ports you wish to leave alone.

By default, SSH (port 22) is in the "do not block" list. You can, of course, change this to 2222 or what not. No support for port knocking yet!

IPv4, IPv6, TCP and UDP are supported. `ltfw` will only ever block ports that it finds acively listening and not whitelisted.

Syntax:

```
Usage:
  ltfw [--quiet|--verbose] [--config=<path>] run
  ltfw -h --help
  ltfw --version

Options:
  -h, --help                Show this screen.
  -v, --version             Show version.
  -c, --config=<file>       Config file.
  -q, --quiet               Suppress output.
  --verbose                 Comprehensive output.
```

Confile file syntax:

```
# If listening on these IPs, they are considered the dangerous ones
closeips = [ "0.0.0.0", "::" ]
# Never block listening on these ports
protectedports = [ "22" ]
# Check every X seconds
every = 60
# Drop (silent) or reject (respond) connections
droporreject = "drop"
```

To run this program as a service, simply create a systemd target file, or a definition file for your favorite process manager.
