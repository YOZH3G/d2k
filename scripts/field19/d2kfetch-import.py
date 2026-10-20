#!/usr/bin/env python3
"""Extract exact probe bytes on the host; reject truncated/malformed transfers."""
import re
from pathlib import Path
import sys
import tempfile


def unpack(bundle, directory):
    with open(bundle, 'rb') as f:
        while True:
            header = f.readline()
            if header == b'DONE\n':
                if f.read(1):
                    raise ValueError('trailing transfer bytes')
                return
            m = re.fullmatch(rb'(probe\.[A-Za-z0-9._-]+) +([0-9]+)\n', header)
            if not m:
                raise ValueError('missing/invalid transfer header')
            size = int(m[2])
            # Stream to disk, so an actual large probe does not consume RAM twice.
            dest = Path(directory) / m[1].decode('ascii')
            partial = None
            try:
                with tempfile.NamedTemporaryFile(mode='wb', dir=directory,
                                                 prefix='.probe-', delete=False) as out:
                    partial = Path(out.name)
                    while size:
                        data = f.read(min(size, 65536))
                        if not data:
                            raise ValueError('truncated ' + dest.name)
                        out.write(data)
                        size -= len(data)
                partial.replace(dest)
            finally:
                if partial is not None and partial.exists():
                    partial.unlink()


if __name__ == '__main__':
    try:
        unpack(sys.argv[1], sys.argv[2])
    except (OSError, ValueError) as e:
        sys.exit('probe transfer: ' + str(e))
