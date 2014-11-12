#!/usr/bin/env python2.7
import qira_config
import qira_program
import time
import math

def ghex(a):
  if a == None:
    return None
  return hex(a).strip("L")

def draw_multigraph(blocks):
  import pydot

  print "generating traces"

  arr = []
  trace = []
  cls = []
  for i in range(len(blocks)):
    h = ghex(blocks[i]['start']) + "-" + ghex(blocks[i]['end']) + "\n" + blocks[i]['dis'].replace("\n", "\\l") + "\\l"
    if h not in arr:
      arr.append(h)
    trace.append(arr.index(h))
    cls.append(blocks[i]['clstart'])


  # this is the whole graph with an edge between each pair
  #print trace
  #print cls

  graph = pydot.Dot(graph_type='digraph')

  print "adding nodes"
  nodes = []
  for a in arr:
    n = pydot.Node(a, shape="box")
    graph.add_node(n)
    nodes.append(n)

  edges = []
  cnts = []

  print "trace size",len(trace)
  print "realblock count",len(arr)

  # coalesce loops
  """
  print "counting edges"
  for i in range(0, len(trace)-1):
    #e = pydot.Edge(nodes[trace[i]], nodes[trace[i+1]], label=str(cls[i+1]), headport="n", tailport="s")
    te = [nodes[trace[i]], nodes[trace[i+1]]]
    if te not in edges:
      edges.append(te)
      cnts.append(1)
    else:
      a = edges.index(te)
      cnts[a] += 1

  print "edge count",len(edges)

  print "adding edges"
  for i in range(len(edges)):
    te = edges[i]
    #print cnts[i]
    if cnts[i] > 1:
      e = pydot.Edge(te[0], te[1], headport="n", tailport="s", color="blue", label=str(cnts[i]))
    else:
      e = pydot.Edge(te[0], te[1], headport="n", tailport="s")
    graph.add_edge(e)
  """

  print "adding edges"
  for i in range(0, len(trace)-1):
    e = pydot.Edge(nodes[trace[i]], nodes[trace[i+1]], label=str(cls[i+1]), headport="n", tailport="s")
    graph.add_edge(e)

  print "drawing png @ /tmp/graph.png"
  graph.write_png('/tmp/graph.png')


def get_blocks(flow, static=True):
  # look at addresses
  # if an address can accept control from two addresses, it starts a basic block
  # if an address can give control to two addresses, it ends a basic block
  #   so add those two addresses to the basic block breaker set

  # address = [all that lead into it]
  prev_map = {}
  next_map = {}

  # address
  prev = None
  next_instruction = None

  basic_block_starts = set()

  dins = {}

  for (address, length, clnum, ins) in flow:
    dins[address] = ins
    if next_instruction != None and next_instruction != address:
      # anytime we don't run the next instruction in sequence
      # this is a basic block starts
      # print next_instruction, address, data
      if static:
        basic_block_starts.add(address)
      #print " ** BLOCK START ** "

    #print clnum, hex(address), length

    if address not in prev_map:
      prev_map[address] = set()
    if prev not in next_map:
      next_map[prev] = set()

    prev_map[address].add(prev)
    next_map[prev].add(address)
    prev = address
    next_instruction = address + length

  # accepts control from two addresses
  for a in prev_map:
    if len(prev_map[a]) > 1:
      basic_block_starts.add(a)
  # gives control to two addresses
  for a in next_map:
    if len(next_map[a]) > 1:
      for i in next_map[a]:
        basic_block_starts.add(i)


  # now with all the addresses that start basic blocks
  # we can break the changelists up based on it
  blocks = []
  cchange = None
  last = None

  def disasm(b, e):
    ret = []
    for i in range(b,e+1):
      if i in dins:
        ret.append(dins[i])
    return '\n'.join(ret)

  for (address, length, clnum, ins) in flow:
    if cchange == None:
      cchange = (clnum, address)
    if address in basic_block_starts:
      blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1], 'dis': disasm(cchange[1], last[1])})
      cchange = (clnum, address)
    last = (clnum, address)

  blocks.append({'clstart': cchange[0], 'clend': last[0], 'start': cchange[1], 'end': last[1], 'dis': disasm(cchange[1], last[1])})
  return blocks

def do_function_analysis(flow):
  next_instruction = None

  fxn_stack = []
  cancel_stack = []
  cl_stack = []

  fxn = []

  for (address, length, clnum, ins) in flow:
    if address in cancel_stack:
      # reran this address, this isn't return
      idx = cancel_stack.index(address)
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "cancel"
    if address in fxn_stack:
      idx = fxn_stack.index(address)
      fxn.append({"clstart":cl_stack[idx],"clend":(clnum-1)})
      fxn_stack = fxn_stack[0:idx]
      cancel_stack = cancel_stack[0:idx]
      cl_stack = cl_stack[0:idx]
      #print map(hex, fxn_stack), clnum, "return"
    elif next_instruction != None and next_instruction != address:
      fxn_stack.append(next_instruction)
      cancel_stack.append(last_instruction)
      cl_stack.append(clnum)
      #print map(hex, fxn_stack), clnum
    next_instruction = address + length
    last_instruction = address
  return fxn

def do_loop_analysis(blocks):
  #blocks = blocks[0:0x30]
  arr = []
  bb = []
  ab = []

  realblocks = []
  realtrace = []

  idx = 0
  for i in range(len(blocks)):
    h = hex(blocks[i]['start']) + "-" + hex(blocks[i]['end'])
    if h not in arr:
      realblocks.append({'start': blocks[i]['start'], 'end': blocks[i]['end'], 'idx': idx})
      idx += 1
      arr.append(h)
    realtrace.append(arr.index(h))
    bb.append(arr.index(h))
    ab.append(i)

  loops = []
  # write this n^2 then make it fast
  did_update = True
  while did_update:
    did_update = False
    for i in range(len(bb)):
      for j in range(1,i):
        # something must run 3 times to make it a loop
        if bb[i:i+j] == bb[i+j:i+j*2] and bb[i:i+j] == bb[i+j*2:i+j*3]:
          loopcnt = 1
          while bb[i+j*loopcnt:i+j*(loopcnt+1)] == bb[i:i+j]:
            loopcnt += 1
          #print "loop",bb[i:i+j],"@",i,"with count",loopcnt
          # document the loop
          loop = {"clstart":blocks[ab[i]]['clstart'],
                  "clendone":blocks[ab[i+j-1]]['clend'],
                  "clend":blocks[ab[i+j*loopcnt]]['clend'],
                  "blockstart":ab[i],
                  "blockend":ab[i]+j-1,
                  "count": loopcnt}
          # remove the loop from the blocks
          bb = bb[0:i] + bb[i:i+j] + bb[i+j*loopcnt:]
          ab = ab[0:i] + ab[i:i+j] + ab[i+j*loopcnt:]
          print loop
          loops.append(loop)
          did_update = True
          break
      if did_update:
        break

  ret = []
  for i in ab:
    t = blocks[i]
    t["blockidx"] = i
    ret.append(t)
  return (ret, loops, realblocks, realtrace)

def get_depth(fxns, clnum):
  d = 0
  for f in fxns:
    if clnum >= f['clstart'] and clnum <= f['clend']:
      d += 1
  return d

def get_depth_map(fxns, maxclnum):
  dderiv = [0]*maxclnum
  for f in fxns:
    dderiv[f['clstart']] += 1
    dderiv[f['clend']] -= 1

  dmap = []
  thisd = 0
  for i in range(maxclnum):
    thisd += dderiv[i]
    dmap.append(thisd)
  return dmap

def convert_reg(trace,ins,cap_reg,arch,tregs,clnum):
  if cap_reg == 0:
    return 0
  if arch == "x86-64":
    x86_64_regs = {"rip" : "RIP", "r12" : "R12", "rbx" : "RBX"}
    cap_name = ins.i.reg_name(cap_reg)
    if cap_name in x86_64_regs:
      reg_name = x86_64_regs[cap_name]
      #get data from registers at this time in the execution
      return trace.db.fetch_registers(clnum)[tregs.index(reg_name)]
    else:
      print "unimplemented capstone reg",cap_name
      return 0
  else:
    print "unimplemented arch",arch
    return 0

#capstone register values to our register values
def process_regs(trace,program,ins,clnum):
  #print "arch",program.static['arch']
  arch = program.static['arch']
  indirect_target = ins.get_indirect_targets()[0][0] #only one right?
  base_reg_cap = indirect_target[0]
  base_reg_val = convert_reg(trace,ins,base_reg_cap,arch,program.tregs[0],clnum)
  index_reg_cap = indirect_target[1]
  index_reg_val = convert_reg(trace,ins,index_reg_cap,arch,program.tregs[0],clnum)
  disp = indirect_target[2]
  print "total_offset",[hex(x) for x in [base_reg_val,index_reg_val,disp]]
  return sum([base_reg_val,index_reg_val,disp])

def get_instruction_flow(trace, program, minclnum, maxclnum):
  start = time.time()
  ret = []
  for i in range(minclnum, maxclnum):
    r = trace.db.fetch_changes_by_clnum(i, 1)
    if len(r) != 1:
      continue

    # this will trigger the disassembly
    ins_temp = program.static[r[0]['address']]['instruction']
    #print "trace",dir(trace)
    #print "trace.db",dir(trace.db)
    if ins_temp.is_indirect_jump():
      #print "found indirect jump"
      #print trace.db.fetch_registers(i)
      print "{}: indirect found".format(i),ins_temp
      print "registers",[hex(x) for x in trace.db.fetch_registers(i)]
      real_jump_addr = process_regs(trace,program,ins_temp,i)
      print "real jump addr",hex(real_jump_addr)
      reg_size = program.tregs[1] #address size always same as reg size?
      print "reg_size",reg_size
      real_jump_target = trace.fetch_memory(i,real_jump_addr,reg_size)#trace.db.fetch_memory(i,real_jump_addr,reg_size)
      try:
        real_target_bytes = [real_jump_target[i] for i in range(reg_size)]
        print "real target:",real_target_bytes
        print "adjusted",[x*(16**i) for i,x in enumerate(real_target_bytes)]
        fixed_values = sum(x*(16**i) for i,x in enumerate(real_target_bytes))
        print hex(fixed_values)

      except:
        pass #no target available
      #add succesor
    ins = str(program.static[r[0]['address']]['instruction'])
    ret.append((r[0]['address'], r[0]['data'], r[0]['clnum'], ins))
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()
  #for ins in ret:
  #  print (hex(ins[0]),ins[1],ins[2],ins[3])
  return ret

def get_hacked_depth_map(flow, program):
  start = time.time()
  return_stack = []
  ret = [0]
  last_clnum = None
  for (address, length, clnum, ins) in flow:
    # handing missing changes
    if last_clnum != None and clnum != last_clnum+1:
      for i in range(clnum-last_clnum-1):
        ret.append(-1)
    last_clnum = clnum

    if address in return_stack:
      return_stack = return_stack[0:return_stack.index(address)]
    # ugh, so gross
    ret.append(len(return_stack))
    for test in program.tregs[4]:
      if ins[0:len(test)] == test:
        return_stack.append(address+length)
        break
    if (time.time() - start) > 0.01:
      time.sleep(0.01)
      start = time.time()
  ret.append(len(return_stack))  # missing last instruction
  return ret

def get_vtimeline_picture(trace, minclnum, maxclnum):
  if trace.maxd == 0:
    return None

  r = maxclnum-minclnum
  sampling = int(math.ceil(r/50000.0))

  from PIL import Image   # sudo pip install pillow
  import base64
  import StringIO
  im_y = int(maxclnum/sampling)
  im = Image.new( 'RGB', (1, im_y), "black")
  px = im.load()

  for i in range(0, r, sampling):
    # could average the sampled
    try:
      if trace.dmap[i] == -1:
        raise Exception("nope")
      c = int((trace.dmap[i]*128.0)/trace.maxd)
      if i/sampling < im_y:
        px[0, i/sampling] = (0,c,c)
    except:
      # make missing changes red
      if i/sampling < im_y:
        px[0, i/sampling] = (96, 32, 32)

  buf = StringIO.StringIO()
  im.save(buf, format='PNG')

  dat = "data:image/png;base64,"+base64.b64encode(buf.getvalue())
  return dat

#def update_indirect_jumps(trace, program):

def analyze(trace, program):
  minclnum = trace.db.get_minclnum()
  maxclnum = trace.db.get_maxclnum()
  """
  if maxclnum > 10000:
    # don't analyze if the program is bigger than this
    return None
  """

  flow = get_instruction_flow(trace, program, minclnum, maxclnum)

  #blocks = get_blocks(flow)
  #print blocks
  #draw_multigraph(blocks)

  #fxns = do_function_analysis(flow)
  #print fxns

  #dmap = get_depth_map(fxns, maxclnum)
  dmap = get_hacked_depth_map(flow)

  #loops = do_loop_analysis(blocks)
  #print loops

def slice(trace, inclnum):
  def is_store(r):
    return r['type'] == "W" or r['type'] == "S"
  def is_load(r):
    return r['type'] == "R" or r['type'] == "L"
  def get_stores(clnum):
    return set(map(lambda x: x['address'], filter(is_store, trace.db.fetch_changes_by_clnum(clnum, 100))))
  def get_loads(clnum):
    return set(map(lambda x: x['address'], filter(is_load, trace.db.fetch_changes_by_clnum(clnum, 100))))

  clnum = inclnum
  st = get_loads(clnum)
  cls = [clnum]

  # so only things before this can affect it
  while clnum > max(0, inclnum-100):
    st.discard(0x10)  # never follow the stack, X86 HAXX
    if len(trace.db.fetch_changes_by_clnum(clnum, 100)) > 20:
      break
    overwrite = st.intersection(get_stores(clnum))
    if len(overwrite) > 0:
      st = st.difference(overwrite)
      st = st.union(get_loads(clnum))
      cls.append(clnum)
      #print clnum, overwrite, st

    """
    r = trace.db.fetch_changes_by_clnum(clnum, 100)
    for e in r:
      print e
    """

    clnum -= 1

  cls = set(cls)
  cls.discard(inclnum)
  return list(cls)

if __name__ == "__main__":
  # can run standalone for testing
  program = qira_program.Program("/tmp/qira_binary", [])
  trace = program.add_trace("/tmp/qira_logs/0", 0)
  while not trace.db.did_update():
    time.sleep(0.1)
  print "loaded"
  program.qira_asm_file = open("/tmp/qira_asm", "r")
  qira_program.Program.read_asm_file(program)

  # *** analysis time ***

  flow = get_instruction_flow(trace, program, trace.db.get_minclnum(), trace.db.get_maxclnum())
  blocks = get_blocks(flow, True)

  print slice(trace, 124)

  #print analyze(t, program)
  #print blocks
  #draw_multigraph(blocks)


