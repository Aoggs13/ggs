"""Reassemble the already-built test IPA without changing ZIP entry contents."""
import hashlib
import struct
import sys
import zipfile
from pathlib import Path

SOURCE_SHA = '30f91a4a024bf55ade9356fa7ec2e0a9c7254a573ad784937aaf4084e7258ebb'
ENTRY_SHA = '972b60a782311b71b40dd662bdec0efc0fb262beb80a683f3c9fe9c99fb9e8c8'
OUTPUT_SHA = 'c6e0adf59d6a7b7d9251c752dcc11c821125d136b52a7f3e67d979219b7e7950'
TARGET = 'Payload/OXIDE.app/Frameworks/ultLoader.framework/ultLoader'
OUTPUT_NAME = 'key.patch.aidos.pc17.ipa'


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def records(path, archive):
    result = {}
    with path.open('rb') as f:
        f.seek(archive.start_dir)
        for info in archive.infolist():
            header = f.read(46)
            if header[:4] != b'PK\x01\x02':
                raise ValueError('Invalid ZIP directory')
            lengths = struct.unpack_from('<HHH', header, 28)
            tail = f.read(sum(lengths))
            if len(tail) != sum(lengths):
                raise ValueError('Truncated ZIP directory')
            result[info.filename] = header + tail
    return result


class DigestWriter:
    def __init__(self):
        self.position = 0
        self.hash = hashlib.sha256()
    def tell(self):
        return self.position
    def write(self, data):
        self.hash.update(data)
        self.position += len(data)


def assemble(source_path, entry_path, output_dir, verify_only=False):
    if digest(source_path) != SOURCE_SHA or digest(entry_path) != ENTRY_SHA:
        raise ValueError('Input SHA-256 mismatch')
    paths = {'source': source_path, 'entry': entry_path}
    archives = {k: zipfile.ZipFile(v) for k, v in paths.items()}
    central = {k: records(paths[k], z) for k, z in archives.items()}
    local_ends = {}
    for k, z in archives.items():
        entries = sorted(z.infolist(), key=lambda i: i.header_offset)
        local_ends[k] = {i.filename: entries[n+1].header_offset if n+1 < len(entries) else z.start_dir for n, i in enumerate(entries)}
    readers = {k: p.open('rb') for k, p in paths.items()}
    output_path = output_dir / OUTPUT_NAME
    output = DigestWriter() if verify_only else output_path.open('wb')
    adjusted = {}
    try:
        for item in sorted(archives['source'].infolist(), key=lambda i: i.header_offset):
            key = 'entry' if item.filename == TARGET else 'source'
            info = archives[key].getinfo(item.filename)
            record = bytearray(central[key][item.filename])
            struct.pack_into('<I', record, 42, output.tell())
            adjusted[item.filename] = record
            reader = readers[key]
            reader.seek(info.header_offset)
            left = local_ends[key][item.filename] - info.header_offset
            while left:
                block = reader.read(min(left, 4*1024*1024))
                if not block:
                    raise ValueError('Unexpected ZIP EOF')
                output.write(block)
                left -= len(block)
        start = output.tell()
        for item in archives['source'].infolist():
            output.write(adjusted[item.filename])
        size = output.tell() - start
        count = len(adjusted)
        comment = archives['source'].comment
        output.write(struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, count, count, size, start, len(comment)))
        output.write(comment)
    finally:
        for f in readers.values():
            f.close()
        if not verify_only:
            output.close()
    actual = output.hash.hexdigest() if verify_only else digest(output_path)
    if actual != OUTPUT_SHA:
        raise ValueError('Output differs from the previously verified test IPA')
    print(f'SHA-256 verified: {actual}')


if __name__ == '__main__':
    assemble(Path(sys.argv[1]), Path(sys.argv[2]), Path.cwd(), '--verify-only' in sys.argv[3:])
