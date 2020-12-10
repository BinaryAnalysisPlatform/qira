import ida_kernwin
import ida_segment
import ida_idaapi
import ida_bytes
import ida_name
import ida_dbg
import ida_ida
import ida_idd
import ida_idp
import threading
import time

wsserver = None
qira_address = None

# this handles all receiving
msg_queue = []  # python array is threadsafe

def handle_message_queue():
  global msg_queue
  while len(msg_queue) > 0:
    dat = msg_queue[0].split(" ")
    msg_queue = msg_queue[1:]

    if dat[0] == "setaddress" and dat[1] != "undefined":
      try:
        a = ida_ida.to_ea(0, int(str(dat[1][2:]),16))
        jump_to(a)
      except e:
        ida_kernwin.msg("[QIRA Plugin] Error processing the address\n")

def start_server():
  global wsserver
  wsserver = SimpleWebSocketServer('', 3003, QiraServer)
  if wsserver is not None:
    ida_kernwin.msg("[QIRA Plugin] Starting WS Server\n")
    wsserver.serveforever()

def set_qira_address(la):
  global qira_address
  ea = 0
  if qira_address is not None and qira_address != ida_idaapi.BADADDR:
    ea = ida_ida.to_ea(0, qira_address)
    ida_dbg.del_bpt(ea)

  qira_address = la
  ida_dbg.add_bpt(qira_address, 0, ida_idd.BPT_SOFT)
  ida_dbg.enable_bpt(qira_address, False)

def jump_to(a):
  global qira_address
  if a is not None:
    if (a != qira_address) and (a != ida_idaapi.BADADDR):
      set_qira_address(a)
      ida_kernwin.jumpto(qira_address, -1, 0)
    else:
      ida_kernwin.jumpto(qira_address, -1, 0)

def ws_send(msg):
  global wsserver
  if (wsserver is not None) and (msg is not None):
    for conn in wsserver.connections.itervalues():
      conn.sendMessage(msg)

def update_address(addr_type, addr):
  if (addr_type is not None) and (addr is not None):
    cmd = "set%s 0x%x" % (addr_type, addr)
    ws_send(cmd)

def update_comment(addr, rpt):
  cmt = ida_bytes.get_cmt(addr, rpt)
  if cmt is not None:
    ws_send("setcmt 0x%x %s" % (addr, cmt))

class MyIDAViewWrapper(ida_kernwin.IDAViewWrapper):
  def __init__(self, viewName):
    ida_kernwin.IDAViewWrapper.__init__(self, viewName)
    self.old_addr = None
    self.addr = None

  def OnViewCurpos(self):
    self.addr = ida_kernwin.get_screen_ea()
    if (self.old_addr != self.addr):
      if (ida_bytes.is_code(ida_bytes.get_flags(self.addr))):
        # don't update the address if it's already the qira address or None
        if (self.addr is not None) and (self.addr != qira_address):
          #idaapi.msg("[QIRA Plugin] Qira Address %x \n" % (self.addr))
          # Instruction Address
          set_qira_address(self.addr)
          update_address("iaddr", self.addr)
      else:
        # Data Address
        update_address("daddr", self.addr)
    self.old_addr = self.addr

class idbhook(ida_idp.IDB_Hooks):
  def cmt_changed(self, a, b):
    update_comment(a, b)
    return 0

class idphook(ida_idp.IDP_Hooks):
  def renamed(self, ea, new_name, local_name):
    #print ea, new_name
    ws_send("setname 0x%x %s" % (ea, new_name))
    return 0
  
class uihook(ida_kernwin.UI_Hooks):
  def __init__(self):
    ida_kernwin.UI_Hooks.__init__(self)
    self.binds = []

  def preprocess(self, arg):
    #print "preprocess", arg
    return 0

  def current_tform_changed(self, a1, a2):
    tm = MyIDAViewWrapper(ida_kernwin.get_widget_title(a1))
    if tm.Bind():
      self.binds.append(tm)
    return 0


class qiraplugin_t(ida_idaapi.plugin_t):
  flags = 0
  comment = "QEMU Interactive Runtime Analyser plugin"
  help = "Visit qira.me for more infos"
  wanted_name = "QIRA Plugin"
  wanted_hotkey = "z"

  def init(self):
    threading.Thread(target=start_server).start()
    ida_kernwin.msg("[QIRA Plugin] Ready to go!\n")
    
    self.w1 = None

    #threading.Thread(target=poll_address).start()

    self.idbhook = idbhook()
    self.idbhook.hook()
    self.idphook = idphook()
    self.idphook.hook()
    self.uihook = uihook()
    self.uihook.hook()

    return ida_idaapi.PLUGIN_KEEP


  def run(self, arg):
    global qira_address
    ida_kernwin.msg("[QIRA Plugin] Syncing with Qira\n")

    # sync names
    for i in range(ida_name.get_nlist_size()):
      ws_send("setname 0x%x %s" % (ida_name.get_nlist_ea(i), ida_name.get_nlist_name(i)))

    # sync comment
    addr = ida_segment.get_segm_base(ida_segment.get_first_seg())
    while addr != ida_idaapi.BADADDR:
      for rpt in [True, False]:
        update_comment(addr, rpt)
      addr = ida_bytes.nextaddr(addr)

  def term(self):
    global wsserver
    if wsserver is not None:
      wsserver.close()
    ida_kernwin.msg("[QIRA Plugin] Plugin uninstalled!\n")


def PLUGIN_ENTRY():
  return qiraplugin_t()



###########################################################
#                                                         #
#    SimpleWebSocketServer                                #
#    https://github.com/opiate/SimpleWebSocketServer.git  #
#                                                         #
###########################################################

'''
The MIT License (MIT)

Copyright (c) 2013 Dave P.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import hashlib
import base64
import socket
import struct
import ssl
import time
import sys
import errno
import logging
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from select import select


class HTTPRequest(BaseHTTPRequestHandler):
  def __init__(self, request_text):
    self.rfile = StringIO(request_text)
    self.raw_requestline = self.rfile.readline()
    self.error_code = self.error_message = None
    self.parse_request()


class WebSocket(object):

  handshakeStr = (
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: WebSocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Protocol: qira\r\n"
    "Sec-WebSocket-Accept: %(acceptstr)s\r\n\r\n"
  )

  hixiehandshakedStr = (
    "HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
    "Upgrade: WebSocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Origin: %(origin)s\r\n"
    "Sec-WebSocket-Protocol: qira\r\n"
    "Sec-WebSocket-Location: %(type)s://%(host)s%(location)s\r\n\r\n"
  )

  GUIDStr = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

  STREAM = 0x0
  TEXT = 0x1
  BINARY = 0x2
  CLOSE = 0x8
  PING = 0x9
  PONG = 0xA

  HEADERB1 = 1
  HEADERB2 = 3
  LENGTHSHORT = 4
  LENGTHLONG = 5
  MASK = 6
  PAYLOAD = 7

  def __init__(self, server, sock, address):
    self.server = server
    self.client = sock
    self.address = address

    self.handshaked = False
    self.headerbuffer = ''
    self.readdraftkey = False
    self.draftkey = ''
    self.headertoread = 2048
    self.hixie76 = False

    self.fin = 0
    self.data = None
    self.opcode = 0
    self.hasmask = 0
    self.maskarray = None
    self.length = 0
    self.lengtharray = None
    self.index = 0
    self.request = None
    self.usingssl = False

    self.state = self.HEADERB1

    # restrict the size of header and payload for security reasons
    self.maxheader = 65536
    self.maxpayload = 4194304

  def close(self):
    self.client.close()
    self.state = self.HEADERB1
    self.hasmask = False
    self.handshaked = False
    self.readdraftkey = False
    self.hixie76 = False
    self.headertoread = 2048
    self.headerbuffer = ''
    self.data = ''


  def handleMessage(self):
    pass

  def handleConnected(self):
    pass

  def handleClose(self):
    pass

  def handlePacket(self):
    # close
    if self.opcode == self.CLOSE:
      self.sendClose()
      raise Exception("received client close")
    # ping
    elif self.opcode == self.PING:
      pass

    # pong
    elif self.opcode == self.PONG:
      pass

    # data
    elif self.opcode == self.STREAM or self.opcode == self.TEXT or self.opcode == self.BINARY:
      self.handleMessage()


  def handleData(self):

    # do the HTTP header and handshake
    if self.handshaked is False:

      data = self.client.recv(self.headertoread)

      if data:
        # accumulate
        self.headerbuffer += data

        if len(self.headerbuffer) >= self.maxheader:
          raise Exception('header exceeded allowable size')

        # we need to read the entire 8 bytes of after the HTTP header, ensure we do
        if self.readdraftkey is True:
          self.draftkey += self.headerbuffer
          read = self.headertoread - len(self.headerbuffer)

          if read != 0:
            self.headertoread = read
          else:
            # complete hixie76 handshake
            self.handshake_hixie76()

        # indicates end of HTTP header
        elif '\r\n\r\n' in self.headerbuffer:
          self.request = HTTPRequest(self.headerbuffer)
          # hixie handshake
          if self.request.headers.has_key('Sec-WebSocket-Key1'.lower()) and self.request.headers.has_key('Sec-WebSocket-Key2'.lower()):
            # check if we have the key in our buffer
            index = self.headerbuffer.find('\r\n\r\n') + 4
            # determine how much of the 8 byte key we have
            read = len(self.headerbuffer) - index
            # do we have all the 8 bytes we need?
            if read < 8:
              self.headertoread = 8 - read
              self.readdraftkey = True
              if read > 0:
                self.draftkey += self.headerbuffer[index:index+read]

            else:
              # get the key
              self.draftkey += self.headerbuffer[index:index+8]
              # complete hixie handshake
              self.handshake_hixie76()

          # handshake rfc 6455
          elif self.request.headers.has_key('Sec-WebSocket-Key'.lower()):
            key = self.request.headers['Sec-WebSocket-Key'.lower()]
            hStr = self.handshakeStr % { 'acceptstr' :  base64.b64encode(hashlib.sha1(key + self.GUIDStr).digest()) }
            self.sendBuffer(hStr)
            self.handshaked = True
            self.headerbuffer = ''

            try:
              self.handleConnected()
            except:
              pass
          else:
            raise Exception('Sec-WebSocket-Key does not exist')

      # remote connection has been closed
      else:
        raise Exception("remote socket closed")

    # else do normal data
    else:
      data = self.client.recv(2048)
      if data:
        for val in data:
          if self.hixie76 is False:
            self.parseMessage(ord(val))
          else:
            self.parseMessage_hixie76(ord(val))
      else:
        raise Exception("remote socket closed")



  def handshake_hixie76(self):

    k1 = self.request.headers['Sec-WebSocket-Key1'.lower()]
    k2 = self.request.headers['Sec-WebSocket-Key2'.lower()]

    spaces1 = k1.count(" ")
    spaces2 = k2.count(" ")
    num1 = int("".join([c for c in k1 if c.isdigit()])) / spaces1
    num2 = int("".join([c for c in k2 if c.isdigit()])) / spaces2

    key = ''
    key += struct.pack('>I', num1)
    key += struct.pack('>I', num2)
    key += self.draftkey

    typestr = 'ws'
    if self.usingssl is True:
      typestr = 'wss'

    response = self.hixiehandshakedStr % { 'type' : typestr, 'origin' : self.request.headers['Origin'.lower()], 'host' : self.request.headers['Host'.lower()], 'location' : self.request.path }

    self.sendBuffer(response)
    self.sendBuffer(hashlib.md5(key).digest())

    self.handshaked = True
    self.hixie76 = True
    self.headerbuffer = ''

    try:
      self.handleConnected()
    except:
      pass


  def sendClose(self):

    msg = bytearray()
    if self.hixie76 is False:
      msg.append(0x88)
      msg.append(0x00)
      self.sendBuffer(msg)
    else:
      pass

  def sendBuffer(self, buff):
    size = len(buff)
    tosend = size
    index = 0

    while tosend > 0:
      try:
        # i should be able to send a bytearray
        sent = self.client.send(str(buff[index:size]))
        if sent == 0:
          raise RuntimeError("socket connection broken")

        index += sent
        tosend -= sent

      except socket.error as e:
        # if we have full buffers then wait for them to drain and try again
        if e.errno == errno.EAGAIN:
          time.sleep(0.001)
        else:
          raise e


  #if s is a string then websocket TEXT is sent else BINARY
  def sendMessage(self, s):

    if self.hixie76 is False:

      header = bytearray()
      isString = isinstance(s, str)

      if isString is True:
        header.append(0x81)
      else:
        header.append(0x82)

      b2 = 0
      length = len(s)

      if length <= 125:
        b2 |= length
        header.append(b2)

      elif length >= 126 and length <= 65535:
        b2 |= 126
        header.append(b2)
        header.extend(struct.pack("!H", length))

      else:
        b2 |= 127
        header.append(b2)
        header.extend(struct.pack("!Q", length))

      if length > 0:
        self.sendBuffer(header + s)
      else:
        self.sendBuffer(header)
      header = None

    else:
      msg = bytearray()
      msg.append(0)
      if len(s) > 0:
        msg.extend(str(s).encode("UTF8"))
      msg.append(0xFF)

      self.sendBuffer(msg)
      msg = None


  def parseMessage_hixie76(self, byte):

    if self.state == self.HEADERB1:
      if byte == 0:
        self.state = self.PAYLOAD
        self.data = bytearray()

    elif self.state == self.PAYLOAD:
      if byte == 0xFF:
        self.opcode = 1
        self.length = len(self.data)
        try:
          self.handlePacket()
        finally:
          self.data = None
          self.state = self.HEADERB1
      else :
        self.data.append(byte)
        # if length exceeds allowable size then we except and remove the connection
        if len(self.data) >= self.maxpayload:
          raise Exception('payload exceeded allowable size')


  def parseMessage(self, byte):
    # read in the header
    if self.state == self.HEADERB1:
      # fin
      self.fin = (byte & 0x80)
      # get opcode
      self.opcode = (byte & 0x0F)

      self.state = self.HEADERB2

    elif self.state == self.HEADERB2:
      mask = byte & 0x80
      length = byte & 0x7F

      if mask == 128:
        self.hasmask = True
      else:
        self.hasmask = False

      if length <= 125:
        self.length = length

        # if we have a mask we must read it
        if self.hasmask is True:
          self.maskarray = bytearray()
          self.state = self.MASK
        else:
          # if there is no mask and no payload we are done
          if self.length <= 0:
            try:
              self.handlePacket()
            finally:
              self.state = self.HEADERB1
              self.data = None

          # we have no mask and some payload
          else:
            self.index = 0
            self.data = bytearray()
            self.state = self.PAYLOAD

      elif length == 126:
        self.lengtharray = bytearray()
        self.state = self.LENGTHSHORT

      elif length == 127:
        self.lengtharray = bytearray()
        self.state = self.LENGTHLONG


    elif self.state == self.LENGTHSHORT:
      self.lengtharray.append(byte)

      if len(self.lengtharray) > 2:
        raise Exception('short length exceeded allowable size')

      if len(self.lengtharray) == 2:
        self.length = struct.unpack_from('!H', str(self.lengtharray))[0]

        if self.hasmask is True:
          self.maskarray = bytearray()
          self.state = self.MASK
        else:
          # if there is no mask and no payload we are done
          if self.length <= 0:
            try:
              self.handlePacket()
            finally:
              self.state = self.HEADERB1
              self.data = None

          # we have no mask and some payload
          else:
            self.index = 0
            self.data = bytearray()
            self.state = self.PAYLOAD

    elif self.state == self.LENGTHLONG:

      self.lengtharray.append(byte)

      if len(self.lengtharray) > 8:
        raise Exception('long length exceeded allowable size')

      if len(self.lengtharray) == 8:
        self.length = struct.unpack_from('!Q', str(self.lengtharray))[0]

        if self.hasmask is True:
          self.maskarray = bytearray()
          self.state = self.MASK
        else:
          # if there is no mask and no payload we are done
          if self.length <= 0:
            try:
              self.handlePacket()
            finally:
              self.state = self.HEADERB1
              self.data = None

          # we have no mask and some payload
          else:
            self.index = 0
            self.data = bytearray()
            self.state = self.PAYLOAD

    # MASK STATE
    elif self.state == self.MASK:
      self.maskarray.append(byte)

      if len(self.maskarray) > 4:
        raise Exception('mask exceeded allowable size')

      if len(self.maskarray) == 4:
        # if there is no mask and no payload we are done
        if self.length <= 0:
          try:
            self.handlePacket()
          finally:
            self.state = self.HEADERB1
            self.data = None

        # we have no mask and some payload
        else:
          self.index = 0
          self.data = bytearray()
          self.state = self.PAYLOAD

    # PAYLOAD STATE
    elif self.state == self.PAYLOAD:
      if self.hasmask is True:
        self.data.append( byte ^ self.maskarray[self.index % 4] )
      else:
        self.data.append( byte )

      # if length exceeds allowable size then we except and remove the connection
      if len(self.data) >= self.maxpayload:
        raise Exception('payload exceeded allowable size')

      # check if we have processed length bytes; if so we are done
      if (self.index+1) == self.length:
        try:
          self.handlePacket()
        finally:
          self.state = self.HEADERB1
          self.data = None
      else:
        self.index += 1


class SimpleWebSocketServer(object):
  def __init__(self, host, port, websocketclass):
    self.websocketclass = websocketclass
    self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.serversocket.bind((host, port))
    self.serversocket.listen(5)
    self.connections = {}
    self.listeners = [self.serversocket]
    self.forceclose = False


  def decorateSocket(self, sock):
    return sock

  def constructWebSocket(self, sock, address):
    return self.websocketclass(self, sock, address)

  def close(self):
    self.serversocket.close()

    for conn in self.connections.itervalues():
      try:
        conn.handleClose()
      except:
        pass

      conn.close()

    self.forceclose = True


  def serveforever(self):
    while True:
      rList, wList, xList = select(self.listeners, [], self.listeners, 1)

      if self.forceclose:
        break

      for ready in rList:
        if ready == self.serversocket:
          try:
            sock, address = self.serversocket.accept()
            newsock = self.decorateSocket(sock)
            newsock.setblocking(0)
            fileno = newsock.fileno()
            self.listeners.append(fileno)
            self.connections[fileno] = self.constructWebSocket(newsock, address)

          except Exception as n:

            logging.debug(str(address) + ' ' + str(n))

            if sock is not None:
              sock.close()
        else:
          client = self.connections[ready]

          try:
            client.handleData()

          except Exception as n:

            logging.debug(str(client.address) + ' ' + str(n))

            try:
              client.handleClose()
            except:
              pass

            client.close()

            del self.connections[ready]
            self.listeners.remove(ready)

      for failed in xList:
        if failed == self.serversocket:
          self.close()
          raise Exception("server socket failed")
        else:
          client = self.connections[failed]

          try:
            client.handleClose()
          except:
            pass

          client.close()

          del self.connections[failed]
          self.listeners.remove(failed)


class SimpleSSLWebSocketServer(SimpleWebSocketServer):

  def __init__(self, host, port, websocketclass, certfile, keyfile, version = ssl.PROTOCOL_TLSv1):

    SimpleWebSocketServer.__init__(self, host, port, websocketclass)

    self.cerfile = certfile
    self.keyfile = keyfile
    self.version = version

  def close(self):
    super(SimpleSSLWebSocketServer, self).close()

  def decorateSocket(self, sock):
    sslsock = ssl.wrap_socket(sock,
                  server_side=True,
                  certfile=self.cerfile,
                  keyfile=self.keyfile,
                  ssl_version=self.version)
    return sslsock

  def constructWebSocket(self, sock, address):
    ws = self.websocketclass(self, sock, address)
    ws.usingssl = True
    return ws

  def serveforever(self):
    super(SimpleSSLWebSocketServer, self).serveforever()



###################
#                 #
#    QIRA CODE    #
#                 #
###################


class QiraServer(WebSocket):
  def handleMessage(self):
    msg_queue.append(self.data)
    ida_kernwin.execute_sync(handle_message_queue, ida_kernwin.MFF_WRITE)

  def handleConnected(self):
    ida_kernwin.msg("[QIRA Plugin] Client connected\n")

  def handleClose(self):
    ida_kernwin.msg("[QIRA Plugin] WebSocket closed\n")

