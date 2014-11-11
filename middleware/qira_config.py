import os,sys

WITH_CDA = False
WITH_DWARF = False
TRACE_LIBRARIES = False
HOST = '127.0.0.1'
WEB_PORT = 3002
SOCAT_PORT = 4000
FORK_PORT = SOCAT_PORT + 1
USE_PIN = False
if os.name == "nt":
  TRACE_FILE_BASE = "c:/qiratmp"
else:
  TRACE_FILE_BASE = "/tmp/qira_logs/"

BASEDIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__))+"/../")
sys.path.append(BASEDIR)
CODESEARCHDIR = BASEDIR+"/cda/codesearch-latest/"
#CODESEARCHDIR = "/usr/bin/"

CALLED_AS_CDA = False

# capstone is now a requirement
WITH_CAPSTONE = True

# turn this off for now on releases
WITH_STATIC = False

WEBSOCKET_DEBUG = False

