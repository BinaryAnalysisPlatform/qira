from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
import struct

def get_arch(fb):
  if fb == 0x28:
    return 'arm'
  elif fb == 0xb7:
    return 'aarch64'
  elif fb == 0x3e:
    return 'x86-64'
  elif fb == 0x03:
    return 'i386'
  elif fb == 0x1400:   # big endian...
    return 'ppc'
  elif fb == 0x800:
    return 'mips'


def load_binary(static, path, debug=False):
  elf = ELFFile(open(path))

  # TODO: replace with elf['e_machine']
  progdat = open(path).read(0x20)
  fb = struct.unpack("H", progdat[0x12:0x14])[0]   # e_machine
  static['arch'] = get_arch(fb)
  static['entry'] = elf['e_entry']

  ncount = 0
  for section in elf.iter_sections():
    addr = section['sh_addr']
    slen = section['sh_size']
    if addr != 0 and slen > 0:
      static.add_memory_chunk(addr, section.data())

    if isinstance(section, RelocationSection):
      symtable = elf.get_section(section['sh_link'])
      if not symtable.is_null(): #check if statically linked
        for rel in section.iter_relocations():
          symbol = symtable.get_symbol(rel['r_info_sym'])
          #print rel, symbol.name
          if rel['r_offset'] != 0 and symbol.name != "":
            static[rel['r_offset']]['name'] = "__"+symbol.name
            if debug:
              static['debug_functions'].add((rel['r_offset'],"__"+symbol.name))
            ncount += 1

    if isinstance(section, SymbolTableSection):
      for nsym, symbol in enumerate(section.iter_symbols()):
        if symbol['st_value'] != 0 and symbol.name != "" and symbol['st_info']['type'] == "STT_FUNC":
          #print symbol['st_value'], symbol.name
          static[symbol['st_value']]['name'] = symbol.name
          if debug:
            static['debug_functions'].add((symbol['st_value'],symbol.name))
          ncount += 1
  #print "** found %d names" % ncount

