keepalink
=========

keepalink is a command-line tool to renew and keep call signs active on the
[WinLink](https://winlink.org) radio email service.

keepalink works by establishing a telnet connection to a WinLink CMS and
logging in with each call sign. It will also indicate if there are messages
waiting to be received.

Usage
-----

```
keepalink MAPFILE
```

`MAPFILE` should be a file containing the call signs and passwords for each of
the accounts to renew.  Each account should be on a separate line in the file,
with the call sign and passwords separated by a comma.

This is essentially a CSV file containing comma-separated values, with no
headers.

If a line is prefixed with `#` it will be ignored.

### Example Map File

```
# This is a comment line

MYCALL, PASSWORD
OTHER, PASSWORD
#IGNORED, PASSWORD
```


Building
--------

Running `make` will produce a `keepalink` binary on Linux and macOS.

Running `make wine` will attempt to use wineg++ to cross-compile for Windows.

Compiling on Windows should be possible with MSVC, but is untested. Pull
requests welcome to add support!

Licence
-------

keepalink is released under the GNU General Public Licence, version 3 or later.

Copyright © 2019 Darryl Pogue
