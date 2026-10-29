#!/usr/bin/env python3

#  keepalink: Command-line tool to renew WinLink accounts
#  Copyright (C) 2026 Darryl Pogue
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

import http.client
import json
import pathlib
import re
import sys

kAuthKey = '3EBF46286B3D4A049929F1FB999F4FD1'

def check_callsign(callsign, password):
    data = { 'Callsign': callsign, 'Password': password, 'Key': kAuthKey }
    headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' }

    try:
        conn = http.client.HTTPSConnection('api.winlink.org')
        conn.request('POST', '/account/password/validate', json.dumps(data).encode(), headers)
        response = conn.getresponse()

        if response.status == 200:
            responsedata = response.read()
            result = json.loads(responsedata.decode('utf-8'))
            return result['IsValid']

        return False
    except:
        return False


def process_file(testfile):
    lines = testfile.read_text().splitlines()
    for idx, line in enumerate(lines):
        if re.match(r'^(#.*)?$', line):
            continue

        callsign, password = line.split(',', 2)
        if not check_callsign(callsign, password):
            lines[idx] = f'#{line}'

    testfile.write_text('\n'.join(lines))


if __name__ == '__main__':
    process_file(pathlib.Path(sys.argv[1]))
