from capstone import *
import capstone # for some unexported (yet) symbols in Capstone 3.0

__all__ = ["Tags", "Function", "Block", "Instruction", "DESTTYPE","ABITYPE"]

class DESTTYPE(object):
  none = 0
  cjump = 1
  jump = 2
  call = 3
  implicit = 4

# Instruction class
class Instruction(object):
  """one disassembled instruction"""
  def __init__(self, raw, address, arch="i386"):
    self.raw = raw
    self.address = address
    if arch == "i386":
      self.md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "x86-64":
      self.md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "thumb":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "arm":
      self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    elif arch == "aarch64":
      self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == "ppc":
      self.md = Cs(CS_ARCH_PPC, CS_MODE_32)
    else:
      raise Exception('arch not supported by capstone')
    self.md.detail = True
    try:
      self.i = self.md.disasm(self.raw, self.address).next()
      self.decoded = True

      self.regs_read = self.i.regs_read
      self.regs_write = self.i.regs_write

      self.dtype = DESTTYPE.none
      if self.i.mnemonic == "call":  # TODO: this is x86 specific
        self.dtype = DESTTYPE.call
      elif self.i.mnemonic == "jmp": # TODO: this is x86 specific
        self.dtype = DESTTYPE.jump
      elif capstone.CS_GRP_JUMP in self.i.groups:
        self.dtype = DESTTYPE.cjump

    #if capstone can't decode it, we're screwed
    except StopIteration:
      self.decoded = False

  def __repr__(self):
    return self.__str__()

  def __str__(self):
    if self.decoded:
      return "%s\t%s"%(self.i.mnemonic,self.i.op_str)
    return ""

  def is_jump(self):
    if not self.decoded:
      return False
    return self.dtype in [DESTTYPE.jump,DESTTYPE.cjump]

  def is_ret(self):
    if not self.decoded:
      return False
    return self.i.mnemonic == "ret"
    #TODO: what about iret? and RET isn't in the apt version of capstone
    return capstone.CS_GRP_RET in self.i.groups

  def is_call(self):
    if not self.decoded:
      return False
    return self.dtype == DESTTYPE.call

  def is_ending(self):
    '''is this something which should end a basic block'''
    if not self.decoded:
      return False
    return self.is_jump() or self.is_ret() or self.i.mnemonic == "hlt"  # TODO: this is x86 specific

  def is_conditional(self):
    if not self.decoded:
      return False
    #TODO shouldn't be x86 specific
    return x86.X86_REG_EFLAGS in self.regs_read  # TODO: this is x86 specific

  def code_follows(self):
    '''should the data after this instructino be treated as code
       note that is_ending is different, as conditional jumps still have
       code that follows'''
    if not self.decoded:
      return False
    #code follows UNLESS we are a return or an unconditional jump
    return not (self.is_ret() or self.dtype == DESTTYPE.jump)

  def size(self):
    return self.i.size if self.decoded else 0

  def dests(self):
    if not self.decoded or self.is_ret():
      return []

    dl = []
    if self.code_follows():
      #this piece of code leads implicitly to the next instruction
      dl.append((self.address+self.size(),DESTTYPE.implicit))

    if self.is_jump() or self.is_call():
      #if we take a PTR and not a MEM or REG operand (TODO: better support for MEM operands)
      #TODO: shouldn't be x86 specific
      if (self.i.operands[0].type == capstone.CS_OP_IMM):
        dl.append((self.i.operands[0].value.imm,self.dtype)) #the target of the jump/call

    return dl

class ABITYPE(object):
  UNKNOWN       = ([],None)
  X86_CDECL     = ([],'EAX')
  X86_FASTCALL  = (['ECX','EDX'],'EAX')
  X86_BFASTCALL = (['EAX','EDX','ECX'],'EAX')
  X64_WIN       = (['RCX','RDX','R8', 'R9'],'RAX')
  X64_SYSV      = (['RDI','RSI','RDX','RCX','R8', 'R9'],'RAX')
  ARM_STD       = (['r0', 'r1', 'r2', 'r3'],'r0')

class Function:
  def __init__(self, start):
    self.start = start
    self.blocks = set()
    self.abi = 'UNKNOWN'
    self.nargs = 0

  def __repr__(self):
    return hex(self.start) + " " + str(self.blocks)

  def add_block(self, block):
    self.blocks.add(block)

  def update_abi(self, abi):
    self.abi = abi

class Block:
  def __init__(self, start):
    self.__start__ = start
    self.addresses = set([start])

  def __repr__(self):
    return hex(self.start())+"-"+hex(self.end())

  def start(self):
    return self.__start__

  def end(self):
    return max(self.addresses)

  def add(self, address):
    self.addresses.add(address)


class Tags:
  def __init__(self, static, address):
    self.backing = {}
    self.static = static
    self.address = address

  def __contains__(self, tag):
    return tag in self.backing

  def __getitem__(self, tag):
    if tag in self.backing:
      return self.backing[tag]
    else:
      # should reading the instruction tag trigger disasm?
      # and should dests be a seperate tag?
      if tag == "instruction":
        dat = self.static.memory(self.address, 0x10)
        # arch should probably come from the address with fallthrough
        self.backing['instruction'] = Instruction(dat, self.address, self.static['arch'])
        self.backing['len'] = self.backing['instruction'].size()
        self.backing['type'] = 'instruction'
        return self.backing[tag]
      if tag == "crefs" or tag == "xrefs":
        # crefs has a default value of a new array
        self.backing[tag] = set()
        return self.backing[tag]
      if tag in self.static.global_tags:
        return self.static.global_tags[tag]
      return None

  def __delitem__(self, tag):
    try:
      del self.backing[tag]
    except:
      pass

  def __setitem__(self, tag, val):
    if tag == "instruction" and type(val) == str:
      raise Exception("instructions shouldn't be strings")
    if tag == "name":
      # name can change by adding underscores
      val = self.static.set_name(self.address, val)
    self.backing[tag] = val

