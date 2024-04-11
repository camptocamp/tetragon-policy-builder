import json


TETRAGON_EVENT_EXEC = 'process_exec'
TETRAGON_EVENT_EXIT = 'process_exit'

class TetragonEvent():

  def __init__(self, e) -> None:
      # Check event type
      if TETRAGON_EVENT_EXEC in e:
        self.type = TETRAGON_EVENT_EXEC
      elif TETRAGON_EVENT_EXIT in e:
        self.type = TETRAGON_EVENT_EXIT
      else:
        eventType = [k for k in e.keys() if k not in ['node_name', 'time']]
        raise Exception("Creation of TetragonEvent for %s is not implemented" % ",".join(eventType))

      process = e[self.type]['process']
      self.exec_id = process["exec_id"]
      if "parent" in e[self.type]:
        self.parent_exec_id = e[self.type]["parent"]["exec_id"]
      else:
        self.parent_exec_ide = None
      self.time = e["time"]
      self.bin = process["binary"]
      try:
        self.args = process["arguments"]
      except KeyError:
        self.args = None

      self.ns = process["pod"]["namespace"]
      self.pod = process["pod"]["name"]
      self.container = process["pod"]["container"]["name"]
      self.container_pid = process["pod"]["container"]["pid"]
      self.workload = process["pod"]["workload"]
      self.workload_kind = process["pod"]["workload_kind"]


  def __eq__(self, other):
    if isinstance(other, TetragonEvent):
        return self.exec_id == other.exec_id                                                        
    else:
        return False
    
  def __str__(self) -> str:
     return f"{self.exec_id} {self.type} {self.workload_kind}/{self.workload} {self.bin}"
    