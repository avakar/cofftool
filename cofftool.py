import argparse, struct, json

class Namespace:
    def __init__(self, **kw):
        for k, v in kw.iteritems():
            setattr(self, k, v)

    def __repr__(self):
        return '{{{}}}'.format(', '.join('{}: {!r}'.format(k, v) for k, v in self.__dict__.iteritems() if not k.startswith('_')))

def parse_coff(fin, offset_base=None):
    offset_base = offset_base or fin

    if fin.read_at(0, 2) == 'MZ':
        (pe_offs,), tail = fin.load_at(0x3c, '<H')
        if fin.read_at(pe_offs, 4) != 'PE\0\0':
            raise RuntimeError('PE signature not found')
        fin = fin[pe_offs+4:]

    header = Namespace()
    (header.machine, header.section_count, header.timestamp, header.symbol_table_ptr,
        header.symbol_count, header.optional_header_size, header.characteristics), tail = fin.load_at(0, '<HHIIIHH')
    optional_header = tail[:header.optional_header_size]
    tail = tail[header.optional_header_size:]

    string_table = {}
    if header.symbol_table_ptr:
        string_data = offset_base[header.symbol_table_ptr + 18*header.symbol_count:]
        (string_table_size,), string_data = string_data.load('<I')
        string_table_data = string_data.read_at(0, string_table_size - 4).split('\x00')[:-1]

        offs = 0
        for s in string_table_data:
            string_table[offs + 4] = s
            offs += len(s) + 1

    sections = []
    for i in xrange(header.section_count):
        section = Namespace()
        (section.name, section.virtual_size, section.virtual_address, section.data_size, section.data_ptr,
            section.reloc_ptr, section.lineno_ptr, section.reloc_count, section.lineno_count, section.flags), tail = tail.load('<8sIIIIIIHHI')
        section.name = section.name.rstrip('\x00')
        if section.name.startswith('/'):
            section.name = string_table[int(section.name[1:], 10)]
        sections.append(section)

    sorted_sections = [sec for sec in sections if sec.data_ptr]
    sorted_sections.sort(key=lambda s: s.data_ptr)
    base_offset = tail.offset(offset_base)
    prev_sec = sorted_sections[0]
    if prev_sec.data_ptr < base_offset:
        raise RuntimeError('section outside bounds')
    content_padding = offset_base[base_offset:prev_sec.data_ptr]
    for sec in sorted_sections[1:]:
        prev_sec.data = offset_base[prev_sec.data_ptr:sec.data_ptr]
        prev_sec = sec
    sorted_sections[-1].data = offset_base[prev_sec.data_ptr:]

    for sec in sections:
        relocs = []
        if sec.reloc_count:
            reloc_data = offset_base[sec.reloc_ptr:]
            reloc = Namespace()
            for i in xrange(sec.reloc_count):
                (reloc.virtual_address, reloc.symbol_table_index, reloc.type), reloc_data = reloc_data.load('<IIH')
            relocs.append(reloc)
        sec.relocs = relocs

    symbol_table = []
    if header.symbol_table_ptr:
        symbol_data = offset_base[header.symbol_table_ptr:]
        symbol_index = 0
        while symbol_index < header.symbol_count:
            sym = Namespace()
            (sym.name, sym.value, sym.section_number, sym.type, sym.storage_class, sym.aux_symbol_count), symbol_data = symbol_data.load('<8sIHHBB')
            if sym.name.startswith('\x00\x00\x00\x00'):
                str_offset = struct.unpack('<I', sym.name[4:])[0]
                sym.name = string_table[str_offset]
            sym.aux, symbol_data = symbol_data.read(sym.aux_symbol_count*18)
            symbol_table.append(sym)
            symbol_index += 1 + sym.aux_symbol_count

    return Namespace(
        offset_base=offset_base,
        header=header,
        optional_header_data=optional_header,
        sections=sections,
        symbol_table=symbol_table)

def parse_pe_file(fin):
    coff = parse_coff(fin)

    coff.dirs = []
    if coff.optional_header_data:
        (magic,), tail = coff.optional_header_data.load('<H')
        if magic == 0x10b:
            opt = Namespace()
            (opt.major_linker_version, opt.minor_linker_version, opt.size_of_code, opt.size_of_initialized_data, opt.size_of_uninitialized_data,
                opt.entry_point, opt.base_of_code, opt.base_of_data), tail = tail.load('<BBIIIIII')
            (opt.image_base, opt.section_align, opt.file_align, opt.os_major, opt.os_minor, opt.image_major, opt.image_minor,
                opt.subsystem_major, opt.subsystem_minor, _, opt.image_size, opt.headers_size, opt.checksum, opt.subsystem,
                opt.dll_characteristics, opt.stack_reserve_size, opt.stack_commit_size, opt.heap_reserve_size, opt.heap_commit_size,
                opt.loader_flags, opt.directory_entry_count), tail = tail.load('<IIIHHHHHHIIIIHHIIIIII')
            coff.optional_header = opt
        else:
            raise RuntimeError('unknown opt header format')

        for i in xrange(opt.directory_entry_count):
            (rva, size), tail = tail.load('<II')
            coff.dirs.append(Namespace(rva=rva, size=size))

    return coff

def slice_by_rva(pe, rva, size=None):
    for sec in pe.sections:
        if not sec.data_ptr:
            continue

        if size is None:
            if sec.data_ptr and sec.virtual_address <= rva and rva <= sec.virtual_address + sec.virtual_size:
                offs = sec.data_ptr + rva - sec.virtual_address
                size = sec.data_size - (offs - sec.data_ptr)
                return pe.offset_base[offs:offs + size]
        else:
            if sec.data_ptr and sec.virtual_address <= rva and rva + size <= sec.virtual_address + sec.virtual_size:
                offs = sec.data_ptr + rva - sec.virtual_address
                if size is None:
                    size = sec.data_size - (offs - sec.data_ptr)
                return pe.offset_base[offs:offs + size]
    else:
        raise RuntimeError('directory not in section')

def slice_pe_dir(pe, dir_index):
    if dir_index >= len(pe.dirs):
        return pe.base_offset[0:0]

    entry = pe.dirs[dir_index]
    if entry.rva == 0:
        return pe.base_offset[0:0]

    return slice_by_rva(pe, entry.rva, entry.size), entry.rva

def map_pe_data(pe, rva, size=None, base=0):
    sp = _VirtualSpace(slice_by_rva(pe, rva, size=size).read()[0], base+rva)
    return ChunkRef(sp, 0, base + rva + len(sp))

def map_pe_dir(pe, dir_index, base=0):
    if dir_index >= len(pe.dirs):
        return None

    entry = pe.dirs[dir_index]
    if entry.rva == 0:
        return None

    sp = map_pe_data(pe, entry.rva, size=entry.size, base=base)
    return sp, sp[entry.rva:]

def parse_export_table(pe):
    raw_data, tail = map_pe_dir(pe, 0)

    d = Namespace()
    (d.flags, d.timestamp, d.major, d.minor, d.name_rva, d.ordinal_base, d.address_table_entries,
        d.name_ptr_count, d.address_table_rva, d.name_pointer_rva, d.ordinal_table_rva), tail  = tail.load('<IIHHIIIIIII')
    dir = d

    def load_string(rva):
        string_data = raw_data[rva:].read()[0]
        return string_data[:string_data.find('\x00')]

    name_table = []
    tail = raw_data[d.name_pointer_rva:]
    for i in xrange(dir.name_ptr_count):
        (name_rva,), tail = tail.load('<I')
        name_table.append(load_string(name_rva))

    return name_table

def parse_lib(fin):
    name, tail = fin.read(8)
    if name != '!<arch>\x0a':
        raise RuntimeError('not a lib')

    members = []
    while tail:
        h = Namespace()
        toks, tail = tail.load('<16s12s6s6s8s10s2s')
        toks = map(lambda s: s.rstrip(' '), toks)
        (h.name, h.date, h.uid, h.gid, h.mode, h.size, h.eoh) = toks
        h.size = int(h.size, 10)
        size = h.size
        if size % 2 != 0:
            size += 1
        h.data = tail[:size]
        tail = tail[size:]
        members.append(h)

    for mem in members:
        if mem.name.startswith('/'):
            continue
        mem.coff = parse_coff(mem.data, mem.data)

    return members

class ChunkRef:
    def __init__(self, reader, offset, size):
        self._reader = reader
        self._offset = offset
        self._size = size

    def __nonzero__(self):
        return bool(self._size)

    def __repr__(self):
        return 'ChunkRef({}, {}, {})'.format(self._offset, self._size, self._reader)

    def __getitem__(self, index):
        if not isinstance(index, slice):
            index = slice(index, index+1)
        start, stop, step = index.indices(self._size)
        if step != 1:
            raise RuntimeError('only step 1 is allowed')
        return ChunkRef(self._reader, self._offset + start, stop - start)

    def offset(self, base):
        assert self._reader is base._reader
        return self._offset - base._offset

    def read(self, size=None):
        if size is None:
            size = self._size
        elif size > self._size:
            raise RuntimeError('Large read')
        return self._reader.read_at(self._offset, size), self[size:]

    def read_at(self, offset, size):
        if offset + size > self._size:
            raise RuntimeError('Large read')
        return self._reader.read_at(offset + self._offset, size)

    def load_at(self, offset, fmt):
        size = struct.calcsize(fmt)
        r = self.read_at(offset, size)
        return struct.unpack(fmt, r), self[offset+size:]

    def load(self, fmt):
        return self.load_at(0, fmt)

class _VirtualSpace:
    def __init__(self, data, base):
        self._data = data
        self._base = base

    def __len__(self):
        return len(self._data)

    def read_at(self, offset, size):
        return self._data[offset-self._base:offset-self._base+size]

def file_chunk(f):
    class Reader:
        def __init__(self, f):
            self._f = f

        def read_at(self, offset, size):
            self._f.seek(offset)
            return self._f.read(size)

    f.seek(0, 2)
    size = f.tell()
    return ChunkRef(Reader(f), 0, size)

def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd')
    ap.add_argument('input')
    args = ap.parse_args()

    if args.cmd == 'print_exports':
        with open(args.input, 'rb') as fin:
            pe = parse_pe_file(file_chunk(fin))
            export_table = parse_export_table(pe)
            print json.dumps(export_table)
    else:
        with open(args.input, 'rb') as fin:
            pe = parse_lib(file_chunk(fin))

if __name__ == '__main__':
    _main()
