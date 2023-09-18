import re
import sys
import signal
import json
import jinja2
import argparse
import time
from collections import defaultdict
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from pprint import pprint
from queue import SimpleQueue, Empty
from threading import Thread, current_thread, Lock


def parse_lines_eol_terminator(filename):
  """
  Yields parsed JSON data from each line of the file.

  Parameters:
  - filename (str): The name of the file to read from.

  Yields:
  - dict: If successful, a dictionary parsed from the JSON string.
  - None: If the line couldn't be parsed as JSON or if any other error occurs.
  """

  with open(filename, 'r') as file:
    for line in file:
      try:
        yield json.loads(line)
      except json.JSONDecodeError as e:
        print(f"Error parsing line as JSON: {e}")
        yield None


def parse_lines_braces_terminator(filename):
  """
  Yields parsed JSON data from file, counts curly braces.

  Parameters:
  - filename (str): The name of the file to read from.

  Yields:
  - dict: If successful, a dictionary parsed from the JSON string.
  - None: If the line couldn't be parsed as JSON or if any other error occurs.
  """
  with open(filename, 'r') as file:
    buffer = []
    brace_count = 0
    for line in file:
      buffer.append(line.strip())
      brace_count += line.count('{') - line.count('}')

      if brace_count == 0 and buffer:
        try:
          yield json.loads(''.join(buffer))
        except json.JSONDecodeError as e:
          print(f"Error parsing lines as JSON: {e}")
          yield None
        buffer = []

def extract_workload_prefix(ns, s):
  """Returns workload id as:

  Assumes pattern
  workload-<rs-id>-<pod-id>
  """
  match = re.match(r'^(.*?)-\d+[a-zA-Z0-9-]+$', s)
  if match:
    return (ns, 'guess-Deployment', match.group(1))
  else:
    # this is very try an error, but we are guessing now workload is a deamon set
    # we assume pattern workload-<pod-id>

      match = re.match(r'^(.*?)-[a-zA-Z0-9]+$', s)
      if match:
        return (ns, 'guess-Deamonset', match.group(1))
      else:
        print(f"Error matching: {s}")
        return None

class EventProcessExec:
  """
  Abstraction layer, describes Tetragon observed events

  """
  def __init__(self, ns ,ctr, bin, wl):
    self.ns = ns
    self.ctr = ctr
    self.bin = bin
    self.wl  = wl

  def originator(self):
    return f"{self.ns}-{self.wl}"

  def __repr__(self) -> str:
    return f"{self.__class__.__name__}(ns='{self.ns}', wl='{self.wl}', bin='{self.bin}')"
    #return "%s(%r)" % (self.__class__.__name__, self.__dict__)

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return False

    return self.ns == other.ns and self.ctr == other.ctr and self.bin == other.bin and self.wl == other.wl

  def __hash__(self):
    return hash(str(f"{repr(self)}"))

class EventProcessExit(EventProcessExec):
  pass

class BufferedDictSet():

  # Dictionary of Set with a modification Buffer
  # to be able to make batch modifications.
  #
  # d = BufferedDictSet()
  # d.add("a", 2)
  # d.add("b", 3) 2 pending modifications
  # d.add("a", 3) 3 pending modifications
  # write_to_disk(d.getDict()) --> {"a": {2, 3}, "b": {3}}
  # d.flush() no more pending modifications

  def __init__(self):
    self.written = dict()
    self.to_write = dict()

  def __str__(self):
    res = "Written:\n"
    for wl, bins in self.written.items():
      res += "%s: %s\n" % (wl, ",".join(bins))
    res += "To write:\n"
    for wl, bins in self.to_write.items():
      res += "%s: %s\n" % (wl, ",".join(bins))
    return res

  # set a value in the 'buffer' if this is not already present
  def add(self, key, value):
    print("Adding %s for %s:\n%s" % (value, key, self))
    if key not in self.written or value not in self.written[key]:
      if key in self.to_write:
        self.to_write[key].add(value)
      else:
        self.to_write[key] = {value}

  def modificationCount(self):
    return len(self.to_write)

  def getDict(self):
    # deep merge !
    res = dict()
    for key in self.written:
      res[key] = self.written[key]
    for key in self.to_write:
      if key in res:
        res[key].update(self.to_write[key])
      else:
        res[key] = self.to_write[key]
    return res

  def flush(self):
    self.written = self.getDict()
    self.to_write = dict()

class PodNotfound(Exception):

  def __init__(self, pod):
    self.pod = pod

  def __str__(self):
    return "Pod not Found: %s" % self.pod

class ReplicasetNotfound(Exception):

  def __init__(self, rs):
    self.rs = rs

  def __str__(self):
    return "Replicaset not Found: %s" % self.rs

class DeploymentNotfound(Exception):

  def __init__(self, deploy):
    self.deploy = deploy

  def __str__(self):
    return "Deployment not Found: %s" % self.deploy

class NotImplemented(Exception):

  def __init__(self, msg):
    self.msg = msg

  def __str__(self):
    return "Not implemented: %s" % self.msg

class NamespaceAnalyser:

  def __init__(self, ns):
    self.ns = ns
    self.pod_to_workload = dict()
    self.wl_selector = dict()
    self.v1 = client.CoreV1Api()
    self.appsv1 = client.AppsV1Api()
    self.binaries = BufferedDictSet()
    self.lock = Lock()

  def getWorkload(self, pod):
    if pod in self.pod_to_workload:
      return self.pod_to_workload[pod]
    else:
      owner = self.getPodOwner(pod)
      if owner[0] == 'ReplicaSet':
        rs_owner = self.getRSOwner(owner[1])
        self.pod_to_workload[pod] = rs_owner
        return rs_owner
      else:
        raise NotImplemented("getWorkload(%s)" % owner[0])

  def getPodOwner(self, pod):
    try:
      api_response = self.v1.read_namespaced_pod(pod, self.ns, pretty=True)
      #pprint(api_response)
      owner = api_response.metadata.owner_references[0]
      return (owner.kind, owner.name)
    except ApiException as e:
      if e.reason == 'Not Found':
        raise PodNotfound(pod)

  def getRSOwner(self, rs):
    try:
      api_response = self.appsv1.read_namespaced_replica_set(rs, self.ns, pretty=True)
      #pprint(api_response)
      owner = api_response.metadata.owner_references[0]
      if owner.kind == "Deployment":
        self.wl_selector["%s-%s" % (owner.kind, owner.name)] = self.getDeploymentSelector(owner.name)
      else:
        raise NotImplemented("getRSOwner(%s)" % owner.kind)
      return (owner.kind, owner.name)
    except ApiException as e:
      if e.reason == 'Not Found':
        raise ReplicasetNotfound(rs)

  def getDeploymentSelector(self, deploy):
    try:
      api_response = self.appsv1.read_namespaced_deployment(deploy, self.ns, pretty=True)
      #pprint(api_response)
      selector = api_response.spec.selector.match_labels
      return selector
    except ApiException as e:
      if e.reason == 'Not Found':
        raise DeploymentNotfound(deploy)


  def process(self, event):
    #print("Searching workload for %s/%s" % (self.ns, event[1]))
    wl = self.getWorkload(event[1])
    #print("Workload for %s/%s is %s" % (self.ns, event[1], wl))

    with self.lock:
      self.binaries.add("%s-%s" % (wl[0], wl[1]), event[2])

  def flush(self):
     print("Flushing binaries for %s" % self.ns)

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
         metadata=client.V1ObjectMeta(name="tetragon-binaries"),
         data={wl: json.dumps(list(value)) for (wl, value) in self.binaries.getDict().items()}
       )
       self.v1.create_namespaced_config_map(namespace=self.ns, body=body)
       self.binaries.flush()

  def modificationCount(self):
    with self.lock:
      return self.binaries.modificationCount()


def export_policy(events: list[EventProcessExec]) -> str:
  """
  Reorganizes data as graph (ns -> wl -> bin)
  Exports data as namespaced TracingPolicies.

  Returns:
    string
  """

  # # # # # # # # #
  # reorganize data

  # events in graph
  graph = defaultdict(lambda: defaultdict(set))
  for item in events:
    graph[item.ns]["%s-%s" % (item.wl[1], item.wl[2])].add(item.bin)\

  # policy template
  template_string = """

{%- for ns, workloads in graph.items() %}
  {%- for wl, bins in workloads.items() %}
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "policy-{{ wl }}-whitelist"
  namespace: "{{ ns }}"
spec:
  tracepoints:
    - subsystem: "raw_syscalls"
      event: "sys_exit"
      args:
      - index: 4
        type: "int64"
      selectors:
      - matchArgs:
        - index: 4
          operator: "Equal"
          values:
          - "59"
          - "322"
        matchBinaries:
        - operator: "NotIn"
          values:
          {%- for bin in bins %}
          - "{{ bin }}"
          {%- endfor %}
        matchActions:
        - action: Sigkill
  #podSelector:
  #  matchLabels:
  #    app.kubernetes.io/instance: {{ wl }}
  # /!\ manual validation needed here ^
  {%- endfor %}
{%- endfor %}

"""

  template = jinja2.Template(template_string)
  rendered = template.render(graph=graph)
  return rendered


def read_pod_log(pod, queue):
  print("%s manage %s" % (current_thread().name, pod.metadata.name))
  v1 = client.CoreV1Api()
  print('In the thread !')
  stream = v1.read_namespaced_pod_log(pod.metadata.name, pod.metadata.namespace, container="export-stdout", follow=True, _preload_content=False)
  while True:
    line = stream.readline()
    if not line:
      time.sleep(1)
      continue

    queue.put(json.loads(line.decode('utf-8')))

def parse_event(e):

    # Extract event type
    eventType = list(e.keys())
    eventType.remove('node_name')
    eventType.remove('time')
    eventType = eventType[0]

    # Only use process_exec events
    if eventType != "process_exec":
      return None

    # Extract metadata
    ns = e[eventType]["process"]["pod"]["namespace"]
    pod = e[eventType]["process"]["pod"]["name"]
    bin = e[eventType]["process"]["binary"]
    return (ns, pod, bin)

class BackgroundFlush(Thread):

  def __init__(self, analyzers):
    self.analyzers = analyzers
    super().__init__()

  def run(self):
    while True:
      time.sleep(10)
      for _, analyzer in self.analyzers.items():
        if analyzer.modificationCount() > 0:
          analyzer.flush()


def main():

  # cli
  parser = argparse.ArgumentParser(description="Process input from stdin or a file.")
  mode = parser.add_mutually_exclusive_group()
  mode.add_argument('--stream-from', type=str, help='stream from the tetragon pods, should contains a pod selector list: app.kubernetes.io/instance=tetragon,app.kubernetes.io/name=tetragon')
  mode.add_argument('--file', type=str, help='path to input file')
  parser.add_argument('--eol-parser', type=str, help='use EOL parser instead of braces count based parser')
  parser.add_argument('--output', type=str, help='path to input file')
  args = parser.parse_args()

  # Load K8S configuration
  config.load_kube_config()

  # states
  analyzers = dict()
  events = []

  def write_policies():
    if args.output:
      with open(args.output, 'w', encoding='utf-8') as f:
        print("writing to file: ", args.output)
        f.write(export_policy(events))
    else:
      print(export_policy(events))

    print("# events parsed")
    for e in events:
      print("#", e)

  # on_exit handler
  def signal_handler(sig, frame):
    write_policies()
    #analyzer.print_stats()
    sys.exit(0)

  signal.signal(signal.SIGINT, signal_handler)

  #  read from the file if --file
  if args.file:
    # set file parser
    if args.eol_parser:
       parser = parse_lines_eol_terminator
    else:
      # default parser uses braces counter
      parser = parse_lines_braces_terminator

    # parse
    for line_number, data in enumerate(parser(args.file), 1):
      if data:
        #print(f"Parsed data from line {line_number}: {data}")
        e = analyzer.process(data)
        if e is None:
          print(f"Couldn't parse data from line number {line_number}.")
        if e not in events:
          events.append(e)
  # read from pods logs
  elif args.stream_from:
    v1 = client.CoreV1Api()

    try:
      pod_list = v1.list_pod_for_all_namespaces(pretty=True, label_selector=args.stream_from)
      #pprint(pod_list)
    except ApiException as e:
      print("Exception when calling CoreV1Api->list_namespaced_pod: %s\n" % e)

    queue = SimpleQueue()
    threads = []

    for pod in pod_list.items:
      t = Thread(name=pod.metadata.name, target=read_pod_log, args=(pod, queue))
      t.start()
      threads.append(t)

    bg_sync = BackgroundFlush(analyzers)
    bg_sync.start()

    # read message from the queue
    msg = None
    while True:
      #print("Waiting for message")
      msg = queue.get(block=True)

      #print("Process one message")
      # Parse event
      event = parse_event(msg)
      if event:
        if event[0] not in analyzers:
          analyzers[event[0]] = NamespaceAnalyser(event[0])
        analyzers[event[0]].process(event)
        if analyzers[event[0]].modificationCount() > 10:
          analyzers[event[0]].flush()


  # else read from stdin
  else:
    for line in sys.stdin:
      data = json.loads(''.join(line))
      e = analyzer.process(data)
      if e is None:
        print(f"Couldn't parse data from line {line}.")
      if e not in events:
        events.append(e)

  # Dump results to file at the end
  write_policies()


if __name__ == "__main__":
  main()
