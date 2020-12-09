import sys 
sys.path.append("middleware/")
import qira_program
import time
import signal

def fail_handler():
  raise Exception("** pthread_test timeout")

def test():
  signal.signal(signal.SIGALRM, fail_handler)
  signal.alarm(7)
  print("\n** thread_test timeout set to 7 second")

  program = qira_program.Program("qira_tests/bin/thread_test")
  program.execqira(shouldfork=False)
  time.sleep(1)

