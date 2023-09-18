import re
import sys
import signal
import json
import yaml
import jinja2
import argparse
import time
import os
from collections import defaultdict
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from pprint import pprint
from queue import SimpleQueue, Empty
from threading import Thread, current_thread, Lock
from flask import Flask, render_template, request, url_for, redirect
from flask_bootstrap import Bootstrap5
from flask_moment import Moment

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
    print("Adding %s for %s:\n%s" % (value, key, self), file=sys.stderr)
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
    self.CRApi = client.CustomObjectsApi()
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
         metadata=client.V1ObjectMeta(name="tetragon-binaries"),
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

class BackgroundFetchEvent(Thread):

  def __init__(self, pod, queue):
    self.pod = pod
    self.queue = queue
    super().__init__()

  def run(self):
    print("%s manage %s" % (current_thread().name, self.pod.metadata.name), file=sys.stderr)
    v1 = client.CoreV1Api()
    stream = v1.read_namespaced_pod_log(self.pod.metadata.name, self.pod.metadata.namespace, container="export-stdout", follow=True, _preload_content=False)
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
      for _, analyzer in self.analyzers.items():
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
      event = self.parseEvent(msg)
      if event:
        if event[0] not in self.analyzers:
          self.analyzers[event[0]] = NamespaceAnalyser(event[0])
        self.analyzers[event[0]].process(event)
        if self.analyzers[event[0]].modificationCount() > 10:
          self.analyzers[event[0]].flush()

  def parseEvent(self, raw_event):

      e = json.loads(raw_event)
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

# Read pod selector to find tetragon pods
tetragon_pod_selector = os.environ.get("TETRAGON_POD_SELECTOR", "app.kubernetes.io/instance=tetragon,app.kubernetes.io/name=tetragon")

# Load K8S configuration
config.load_kube_config()

# Load Flask App
app = Flask(__name__)
Bootstrap5(app)
Moment(app)

# states
analyzers = dict()
events = []
queue = SimpleQueue()

# read from pods logs
v1 = client.CoreV1Api()

# Search for tetragon pods
pod_list = v1.list_pod_for_all_namespaces(pretty=True, label_selector=tetragon_pod_selector)

# Starts thread to fetch log from pods
for pod in pod_list.items:
  t = BackgroundFetchEvent(pod, queue)
  t.start()

# Start the process to store data in configmaps
bg_sync = BackgroundFlush(analyzers)
bg_sync.start()

# Start the process to consume pod logs
bg_analyzer = BackgroundAnalyser(analyzers, queue)
bg_analyzer.start()

@app.route("/")
def home():
  return render_template('index.html', analyzers=analyzers)

@app.route('/remove_binary', methods=['POST'])
def remove_binary():
  ns = request.form.get('ns')
  wl = request.form.get('wl')
  binary = request.form.get('binary')
  analyzers[ns].forgot(wl, binary)
  return "Removed"

app.run()
