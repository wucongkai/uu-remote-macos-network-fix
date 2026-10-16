#!/usr/bin/env python3
"""UU-only loopback CONNECT proxy; TLS stays encrypted and verified by UU."""
import argparse, ipaddress, logging, select, socket, socketserver, struct, threading, time
from logging.handlers import RotatingFileHandler

ALLOWED_SUFFIXES=('163.com','netease.com','gameviewer.com','126.net','127.net')
DNS_SERVERS=('223.5.5.5','119.29.29.29')
CACHE={}
LOCK=threading.Lock()

def recv_exact(sock,n):
 data=b''
 while len(data)<n:
  part=sock.recv(n-len(data))
  if not part:raise ConnectionError('connection closed')
  data+=part
 return data

def skip_name(data,pos):
 while True:
  size=data[pos]
  if size&0xc0==0xc0:return pos+2
  pos+=1
  if not size:return pos
  pos+=size

def resolve(host):
 try:return str(ipaddress.IPv4Address(host))
 except ValueError:pass
 now=time.monotonic()
 with LOCK:
  saved=CACHE.get(host)
  if saved and saved[1]>now:return saved[0]
 qid=__import__('secrets').randbits(16)
 question=b''.join(bytes([len(label)])+label.encode('ascii') for label in host.split('.'))+b'\0'+struct.pack('!HH',1,1)
 packet=struct.pack('!HHHHHH',qid,0x100,1,0,0,0)+question
 last=None
 for server in DNS_SERVERS:
  try:
   with socket.create_connection((server,53),timeout=3) as s:
    s.sendall(struct.pack('!H',len(packet))+packet)
    reply=recv_exact(s,int.from_bytes(recv_exact(s,2),'big'))
   ident,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',reply[:12])
   if ident!=qid or flags&15:raise OSError('DNS response error')
   pos=12
   for _ in range(qd):pos=skip_name(reply,pos)+4
   ips=[];ttl=300
   for _ in range(an):
    pos=skip_name(reply,pos)
    rtype,rclass,rttl,length=struct.unpack('!HHIH',reply[pos:pos+10]);pos+=10
    value=reply[pos:pos+length];pos+=length
    if rtype==1 and rclass==1 and length==4:
     ip=socket.inet_ntoa(value)
     if ipaddress.ip_address(ip).is_global:ips.append(ip);ttl=min(ttl,rttl)
   if not ips:raise OSError('DNS no public IPv4 address')
   with LOCK:CACHE[host]=(ips[0],now+max(10,ttl))
   return ips[0]
  except (OSError,ValueError,IndexError,struct.error) as e:last=e
 raise OSError('TCP DNS resolution failed') from last

def allowed(host):
 return any(host==suffix or host.endswith('.'+suffix) for suffix in ALLOWED_SUFFIXES)

def forward_initial(client,upstream,host):
 # Only the framing of the plaintext ClientHello record changes. The TLS
 # transcript, certificates, encrypted payload and application bytes are intact.
 client.settimeout(8)
 first=recv_exact(client,1)
 logging.info('tunnel start host=%s record_type=%d',host,first[0])
 if first!=b'\x16':
  upstream.sendall(first);return
 rest=recv_exact(client,4);header=first+rest
 size=int.from_bytes(header[3:5],'big')
 logging.info('TLS ClientHello host=%s version=%s length=%d',host,header[1:3].hex(),size)
 if size>18432:raise ValueError('oversized TLS record')
 payload=recv_exact(client,size)
 needle=host.encode('ascii')
 at=payload.lower().find(needle.lower())
 cut=1
 if not 0<cut<size:upstream.sendall(header+payload);return
 upstream.sendall(header[:3]+cut.to_bytes(2,'big')+payload[:cut])
 time.sleep(.02)
 upstream.sendall(header[:3]+(size-cut).to_bytes(2,'big')+payload[cut:])

def relay(a,b):
 a.settimeout(None);b.settimeout(None)
 totals=[0,0];initial=[True,True]
 while True:
  ready,_,_=select.select([a,b],[],[],300)
  if not ready:return
  for source in ready:
   target=b if source is a else a
   data=source.recv(65536)
   if not data:
    logging.info('tunnel closed direction=%s client_bytes=%d server_bytes=%d', 'client' if source is a else 'server',*totals);return
   index=0 if source is a else 1
   totals[index]+=len(data)
   if initial[index]:
    initial[index]=False
    logging.info('tunnel first direction=%s record_type=%d bytes=%d','client' if index==0 else 'server',data[0],len(data))
   target.sendall(data)

class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  upstream=None;host='unknown';connected=False
  try:
   self.connection.settimeout(10)
   initial=self.connection.recv(1,socket.MSG_PEEK)
   if initial==b'\x05':
    self.handle_socks5();return
   logging.info('client protocol=HTTP')
   request=self.rfile.readline(8193)
   if len(request)>8192:return
   parts=request.decode('ascii').strip().split()
   if len(parts)!=3:return
   method,target,version=parts
   if method!='CONNECT':
    self.wfile.write(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return
   host,port_text=target.rsplit(':',1);host=host.lower().rstrip('.');port=int(port_text)
   if not allowed(host) or port!=443:
    logging.warning('denied host=%s port=%d',host,port)
    self.wfile.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');return
   total=0
   while True:
    line=self.rfile.readline(8193);total+=len(line)
    if total>32768:raise ValueError('oversized headers')
    if line in (b'\r\n',b'\n'):break
    if not line:raise ConnectionError('incomplete request')
   ip=resolve(host)
   upstream=socket.create_connection((ip,port),timeout=6)
   self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');self.wfile.flush();connected=True
   # rbufsize=0 ensures no ClientHello bytes are hidden in a buffered reader.
   forward_initial(self.connection,upstream,host)
   logging.info('connected host=%s ip=%s',host,ip)
   relay(self.connection,upstream)
  except (OSError,ValueError,UnicodeError) as e:
   logging.warning('failed host=%s error=%s',host,type(e).__name__)
   if not connected:
    try:self.wfile.write(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
    except OSError:pass
  finally:
   if upstream:upstream.close()
 def handle_socks5(self):
  upstream=None;host='unknown'
  try:
   version,count=recv_exact(self.connection,2)
   methods=recv_exact(self.connection,count)
   if 0 not in methods:
    self.connection.sendall(b'\x05\xff');return
   self.connection.sendall(b'\x05\x00')
   version,command,reserved,kind=recv_exact(self.connection,4)
   if kind==3:host=recv_exact(self.connection,recv_exact(self.connection,1)[0]).decode('ascii').lower().rstrip('.')
   elif kind==1:host=socket.inet_ntoa(recv_exact(self.connection,4))
   elif kind==4:host=socket.inet_ntop(socket.AF_INET6,recv_exact(self.connection,16))
   else:raise ValueError('invalid SOCKS address type')
   port=int.from_bytes(recv_exact(self.connection,2),'big')
   logging.info('client protocol=SOCKS5 host=%s port=%d',host,port)
   try:ip=ipaddress.ip_address(host);permitted=ip.is_global
   except ValueError:permitted=allowed(host)
   if version!=5 or command!=1 or not permitted or port!=443:
    self.connection.sendall(b'\x05\x02\x00\x01'+b'\0'*6);return
   ip=resolve(host)
   upstream=socket.create_connection((ip,port),timeout=6)
   self.connection.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
   forward_initial(self.connection,upstream,host)
   logging.info('connected SOCKS5 host=%s ip=%s',host,ip)
   relay(self.connection,upstream)
  except (OSError,ValueError,UnicodeError) as e:
   logging.warning('failed SOCKS5 host=%s error=%s',host,type(e).__name__)
  finally:
   if upstream:upstream.close()
 rbufsize=0

class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
 request_queue_size=64

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=17891);parser.add_argument('--log')
 args=parser.parse_args()
 handlers=[RotatingFileHandler(args.log,maxBytes=524288,backupCount=2,encoding='utf-8')] if args.log else [logging.StreamHandler()]
 logging.basicConfig(handlers=handlers,level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
 with Server(('127.0.0.1',args.port),Handler) as server:
  logging.info('UU connection adapter listening on 127.0.0.1:%d',args.port)
  server.serve_forever()
