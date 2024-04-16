from datetime import datetime
import sys
import json
import yaml
import time
import os
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from pprint import pprint
from queue import SimpleQueue, Empty
from threading import Thread, current_thread, Lock
from tetragon_event import TetragonEvent, TETRAGON_EVENT_EXEC, TETRAGON_EVENT_EXIT
from utils import *

TIME_30_DAYS = 3600*24*30 # seconds
TIME_3_DAYS = 3600*24*3 # seconds

class NamespaceAnalyser:

  def __init__(self, ns):
    self.ns = ns
    #self.pod_to_workload = dict()
    #self.wl_selector = dict()
    self.v1 = client.CoreV1Api()
    self.appsv1 = client.AppsV1Api()
    self.CRApi = client.CustomObjectsApi()
    self.binaries = BufferedDictSet()
    # Populate binaries from configmap
    self._loadBinariesFromCM()
    self.lock = Lock()
    #self.orphanPod = set()
    self.workloads : dict[str: Workload] = {}

  def _loadBinariesFromCM(self):
    try:
      print("Loading binaries from ConfigMap %s/tetragon-binaries" % self.ns)
      api_response = self.v1.read_namespaced_config_map("tetragon-binaries", self.ns, pretty=True)
      self.binaries.written = { wl: set(json.loads(bins)) for (wl, bins) in api_response.data.items()}
      print("%s/tetragon-binaries ConfigMap found" % self.ns)
      print(self.binaries)
    except ApiException as e:
      if e.reason == 'Not Found':
        print("%s/tetragon-binaries ConfigMap not found" % self.ns)
      else:
        raise e

  # Namespace
  #   Workload
  #     ExecTree
  #       Processus


  def processEvent(self, event : TetragonEvent):
    with self.lock:
      # Create or fetch Workload
      wl_id = f"{event.workload_kind}-{event.workload}"
      if wl_id not in self.workloads:
        self.workloads[wl_id] = Workload(event.workload_kind, event.workload)
      wl = self.workloads[wl_id]

      #print(event)

      # Forward event to the workload
      self.binaries.add(f"{event.workload_kind}-{event.workload}", event.bin)
      for tree in wl.trees:
        if tree.processEvent(event):
          # event was bound to a process tree,
          # no need to inspect other workloads
          print(self)
          return
      # Seems to be a new process tree:
      # * entrypoint
      # * kubectl exec
      if event.container_pid == 1:
        print("Entrypoint detected")
      else:
        print("User initiated process tree")
      # the event should be the root process of the new tree
      wl.trees.append(ExecTree(event))
      print(self)


  def forgot(self, wl, binary):
    if wl in self.binaries.written and binary in self.binaries.written[wl]:
      self.binaries.written[wl].discard(binary)
      self.flush()
    else:
      self.binaries.to_write[wl].discard(binary)

  def flush(self):
     print("Flushing binaries for %s" % self.ns, file=sys.stderr)

     # Delete current configmap
     with self.lock:
       try:
         self.v1.delete_namespaced_config_map("tetragon-binaries", self.ns)
       except Exception as ex:
         pass

       # Create configmap
       body = client.V1ConfigMap(
         api_version="v1",
         kind="ConfigMap",
         metadata=client.V1ObjectMeta(name="tetragon-binaries", labels={"generated-by": "tetragon-policy-builder"}),
         data={wl: json.dumps(list(value)) for (wl, value) in self.binaries.getDict().items()}
       )
       self.v1.create_namespaced_config_map(namespace=self.ns, body=body)
       self.binaries.flush()

  def modificationCount(self):
    with self.lock:
      return self.binaries.modificationCount()

  def generatePolicy(self, wl):

      manifest = {
        "apiVersion": "cilium.io/v1alpha1",
        "kind": "TracingPolicyNamespaced",
        "metadata": {
          "name": wl.lower(),
          "namespace": self.ns,
        },
        "spec": {
          "podSelector": {
            "matchLabels" : self.wl_selector[wl]
          },
          "tracepoints": [
            {
              "subsystem": "raw_syscalls",
              "event": "sys_exit",
              "args": [ { "index": 4, "type": "int64"} ],
              "selectors": [
                {
                  "matchArgs": [ { "index": 4, "operator": "Equal", "values": ["59", "322"] } ],
                  "matchBinaries": [ { "operator": "NotIn", "values": list(self.binaries.getDict()[wl]) } ],
                  "matchActions": [ { "action": "Sigkill" } ]
                }
              ]
            }
          ]
        }
      }
      #pprint(manifest)
      return manifest

  def deployPolicy(self, wl):
    self.CRApi.create_namespaced_custom_object(
        group="cilium.io",
        version="v1alpha1",
        namespace=self.ns,
        plural="tracingpoliciesnamespaced",
        body=self.generatePolicy(wl),
    )

  def updatePolicy(self, wl):
    if self.policyExists(wl):
      self.deletePolicy(wl)
    self.deployPolicy(wl)

  def deletePolicy(self, wl):
    self.CRApi.delete_namespaced_custom_object(
        group="cilium.io",
        version="v1alpha1",
        name=wl.lower(),
        namespace=self.ns,
        plural="tracingpoliciesnamespaced",
    )

  def policyExists(self, wl):
    try:
      resource = self.CRApi.get_namespaced_custom_object(
        group="cilium.io",
        version="v1alpha1",
        name=wl.lower(),
        namespace=self.ns,
        plural="tracingpoliciesnamespaced",
      )
    except ApiException as e:
      if e.status == 404:
        return False
      else:
        raise e
    return True

  def getBinariesInPolicy(self, wl):
    try:
      resource = self.CRApi.get_namespaced_custom_object(
        group="cilium.io",
        version="v1alpha1",
        name=wl.lower(),
        namespace=self.ns,
        plural="tracingpoliciesnamespaced",
      )
    except ApiException as e:
      if e.status == 404:
        return None
      else:
        raise e
    return resource['spec']['tracepoints'][0]['selectors'][0]['matchBinaries'][0]['values']

  def __str__(self):
    title = f"Namespace: {self.ns}"
    res = title + "\n" + ('-' * len(title)) + "\n"
    for key, wl in self.workloads.items():
      res += str(wl) + "\n"
    return res


class BackgroundFetchEvent(Thread):

  def __init__(self, pod, queue):
    self.pod = pod
    self.queue = queue
    super().__init__()

  def run(self):
    print("%s manage %s" % (current_thread().name, self.pod.metadata.name), file=sys.stderr)
    v1 = client.CoreV1Api()
    stream = v1.read_namespaced_pod_log(self.pod.metadata.name, self.pod.metadata.namespace, container="export-stdout", follow=True, _preload_content=False, since_seconds=TIME_3_DAYS)
    while True:
      line = stream.readline()
      if not line:
        time.sleep(1)
        continue
      self.queue.put(line.decode('utf-8'))

class BackgroundFlush(Thread):

  def __init__(self, analyzers):
    self.analyzers = analyzers
    super().__init__()

  def run(self):
    while True:
      time.sleep(10)
      for _, analyzer in self.analyzers.copy().items():
        if analyzer.modificationCount() > 0:
          analyzer.flush()

class BackgroundAnalyser(Thread):

  def __init__(self, analyzers, queue):
    self.analyzers = analyzers
    self.queue = queue
    super().__init__()

  def run(self):
    # read message from the queue
    while True:
      #print("Waiting for message")
      msg = self.queue.get(block=True)

      #print("Process one message")
      # Parse event
      try:
        event = TetragonEvent(json.loads(msg))
        if event.ns not in self.analyzers:
          self.analyzers[event.ns] = NamespaceAnalyser(event.ns)
        self.analyzers[event.ns].processEvent(event)
        if self.analyzers[event.ns].modificationCount() > 10:
          self.analyzers[event.ns].flush()
      except Exception as e:
        pass

      # Check if event is part of a user initiated session


class Workload():
  """
  Hold exec trees of a specific workload and list of binary used
  """

  def __init__(self, workload_kind, workload) -> None:
    self.workload = workload
    self.workload_kind = workload_kind
    self.trees: list[ExecTree] = []

  def __str__(self):
    title = f"{self.workload_kind}: {self.workload}"
    res = "  " + title + "\n  " + ('-' * len(title)) + "\n"
    for tree in self.trees:
      res += str(tree) + "\n"
    return res


class ExecTree():
  """One exec tree per container corresponding to the entrypoint
  some additional exec tree may be created by user initiated session
  """

  def __init__(self, first_event: TetragonEvent) -> None:
    self.root_command : Processus = Processus(first_event)
    self.description = f"{first_event.workload_kind}-{first_event.workload}-{first_event.container}-{"entrypoint" if self.is_entrypoint() else "exec"}"

  def processEvent(self, exec_exit_event: TetragonEvent) -> bool:
    """This method process TetragonEvent.
    The even
    return true if the process is part of this tree
    """
    # check if this event belong to this tree
    parent : Processus = self.root_command.findProcessus(exec_exit_event.parent_exec_id)
    if not parent:
      return False

    # Check if the process is already in the tree
    process : Processus = self.root_command.findProcessus(exec_exit_event.exec_id)
    if process:
        process.processEvent(exec_exit_event)
    else:
        parent.addChildProcessus(Processus(exec_exit_event))
        #print("Process %s/%s  adopted by %s/%s"
        #        % (exec_exit_event.exec_id, exec_exit_event.bin, self.root_command.exec_id, self.root_command.bin))

    # The process was adopted by this exec tree, let's notice caller by returning true
    return True

  def is_entrypoint(self):
    """True if entrypoint of container, else  -e.g. kubectl exec initiated process-- it will return false
    """
    return str(self.root_command.container_pid) == "1"

  def get_json(self):
    return self.root_command.get_json()

  def getBinaries(self):
    return self.root_command.getBinaries()

  def __str__(self):
    return self.root_command.print(4)

class Processus:
  """Abstraction for accessing Kubernetes Workloads' processes data.
  Process objects are fed with Tetragon events, which are nothing more than Tetragon observations of system calls.
  Data include cluster-wide unique identifiers, binaries executed, start time, end time and also hierarchical linked information about parent/child dependence.

  Note: Given that events may not be received in the right order, Processus objects can be initiated on type Exec or Exit.
  """

  def __init__(self, tetragon_event: TetragonEvent) -> None:
    self.start_time = None
    self.stop_time = None

    # TODO Should be removed later to reduce memory footprint
    self.exec_event = None
    self.exit_event = None
    # Check type of event
    if tetragon_event.type == TETRAGON_EVENT_EXEC:
      self.start_time = tetragon_event.time
      self.exec_event = tetragon_event
    elif tetragon_event.type == TETRAGON_EVENT_EXIT:
      self.stop_time = tetragon_event.time
      self.exit_event = tetragon_event
    else:
      raise Exception("Unknown event")
      #raise Exception("Cannot create a process with an exit event")

    # Tetragon identifier
    self.exec_id = tetragon_event.exec_id
    self.container_pid = tetragon_event.container_pid
    self.bin = tetragon_event.bin
    self.args = tetragon_event.args
    self.childs = []

  def _get_state(self):
    if self.start_time and self.stop_time:
      return "completed"
    elif self.start_time:
      return "running"
    else:
      return "incoherent"

  def processEvent(self, tetragon_event: TetragonEvent) -> None:
    if tetragon_event.type == TETRAGON_EVENT_EXEC:
      self.start_time = tetragon_event.time
      self.exec_event = tetragon_event
    elif tetragon_event.type == TETRAGON_EVENT_EXIT:
      self.stop_time = tetragon_event.time
      self.exit_event = tetragon_event
      # TODO Check reason of the exit event : sigkill ?
      # self.exit_reason = ...
    else:
      raise Exception("Unknown event")

  def addChildProcessus(self, child) -> None:
    self.childs.append(child)

  def findProcessus(self, exec_id):
    if self.exec_id == exec_id:
      return self
    else:
      for child in self.childs:
        p = child.findProcessus(exec_id)
        if p:
          return p
      return None

  def getBinaries(self):
    bins = [self.exec_event.bin]
    for child in self.childs:
      bins.extend(child.getBinaries())
    return bins

  def get_json(self):
    res=[self.as_json()]
    for child in self.childs:
      res.extend(child.get_json())
    return res

  def as_json(self):
    return {
      'content': f"{self.bin} {self.args}",
      'start': self.start_time if self.start_time else "",
      'end': self.stop_time if self.stop_time else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
      'className': self._get_state(),
    }

  def print(self, indentation):
    state = self._get_state().upper()
    res = f"{' ' * indentation}PID: {str(self.exec_event.container_pid)} {str(self.bin)} ({state})\n"
    for child in self.childs:
      res += child.print(indentation + 2)
    return res
