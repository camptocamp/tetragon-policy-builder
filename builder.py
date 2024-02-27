import sys
import json
import uuid
import yaml
import time
import os
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException
from pprint import pprint
from queue import SimpleQueue, Empty
from threading import Thread, current_thread, Lock
from flask import Flask, render_template, request, url_for, redirect, jsonify
from flask_bootstrap import Bootstrap5
from flask_moment import Moment
from utils import *

BUFFER_SIZE = 10

class NamespaceAnalyser:

  def __init__(self, ns):
    self.ns = ns
    self.pod_to_workload = dict()
    self.wl_selector = dict()
    self.v1 = client.CoreV1Api()
    self.appsv1 = client.AppsV1Api()
    self.CRApi = client.CustomObjectsApi()
    self.binaries = BufferedDictSet()
    # Populate binaries from configmap
    self._loadBinariesFromCM()
    self.lock = Lock()
    self.orphanPod = set()
    self.events_tail = Buffer(BUFFER_SIZE)

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

  def getWorkload(self, pod):
    if pod in self.pod_to_workload:
      return self.pod_to_workload[pod]
    else:
      if pod in self.orphanPod:
        raise PodNotfound(pod)
      owner = self.getPodOwner(pod)
      if not owner:
        return "unknown"
      elif owner[0] == 'ReplicaSet':
        rs_owner = self.getRSOwner(owner[1])
        self.pod_to_workload[pod] = rs_owner
        return rs_owner
      elif owner[0] == 'DaemonSet':
        self.pod_to_workload[pod] = owner
        self.wl_selector["%s-%s" % (owner[0], owner[1])] = self.getDaemonSetSelector(owner[1])
        return owner
      elif owner[0] == 'StatefulSet':
        self.pod_to_workload[pod] = owner
        self.wl_selector["%s-%s" % (owner[0], owner[1])] = self.getStatefulSetSelector(owner[1])
        return owner
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
        self.orphanPod.add(pod)
        raise PodNotfound(pod)
      else:
        raise e
    except TypeError as e:
      pprint(api_response)

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
      else:
        raise e

  def getDeploymentSelector(self, deploy):
    try:
      api_response = self.appsv1.read_namespaced_deployment(deploy, self.ns, pretty=True)
      #pprint(api_response)
      selector = api_response.spec.selector.match_labels
      return selector
    except ApiException as e:
      if e.reason == 'Not Found':
        raise DeploymentNotfound(deploy)
      else:
        raise e

  def getDaemonSetSelector(self, ds):
    try:
      api_response = self.appsv1.read_namespaced_daemon_set(ds, self.ns, pretty=True)
      #pprint(api_response)
      selector = api_response.spec.selector.match_labels
      return selector
    except ApiException as e:
      if e.reason == 'Not Found':
        raise DaemonSetNotfound(ds)
      else:
        raise e

  def getStatefulSetSelector(self, sts):
    try:
      api_response = self.appsv1.read_namespaced_stateful_set(sts, self.ns, pretty=True)
      #pprint(api_response)
      selector = api_response.spec.selector.match_labels
      return selector
    except ApiException as e:
      if e.reason == 'Not Found':
        raise StatefulSetNotfound(sts)
      else:
        raise e

  def process(self, event):
    try:
      #print("Searching workload for %s/%s" % (self.ns, event[1]))
      tail = self.events_tail.get()
      if len(tail)>0:
        pprint(tail)
      else:
        print('no events in tail buffer')

      wl = self.getWorkload(event[1])
      print("Workload for %s/%s is %s" % (self.ns, event[1], wl))

      with self.lock:
        print(event)
        self.binaries.add("%s-%s" % (wl[0], wl[1]), event[2])
        self.events_tail.append(
          # return (ns 0, pod, bin, args, start, auid 5)
          {
          'id': event[5], # auid
          'content': '{} {}'.format(event[2],event[3]), # bin info
          'start': event[4], # start process time
          'group': wl[1],
          }
        )

    except PodNotfound as e:
      print(e)

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

  def getEvents(self):
    return self.events_tail.get()


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

      # print("parsing event")
      # pprint(e)

      # Extract metadata
      ns = e[eventType]["process"]["pod"]["namespace"]
      pod = e[eventType]["process"]["pod"]["name"]
      bin = e[eventType]["process"]["binary"]
      try:
        args = e[eventType]["process"]["arguments"]
      except KeyError:
        args = ""
      start = e[eventType]["process"]["start_time"]
      #auid = e[eventType]["process"]["auid"]
      auid = uuid.uuid4()
      return (ns, pod, bin, args, start, auid)

# Read pod selector to find tetragon pods
tetragon_pod_selector = os.environ.get("TETRAGON_POD_SELECTOR", "app.kubernetes.io/instance=tetragon,app.kubernetes.io/name=tetragon")

# Load K8S configuration
try:
  config.load_kube_config()
except ConfigException:
  config.load_incluster_config()

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
  return render_template('index.html', analyzers=analyzers.copy())

@app.route("/health")
def health():
  return "OK"

@app.route('/remove_binary', methods=['POST'])
def remove_binary():
  ns = request.form.get('ns')
  wl = request.form.get('wl')
  binary = request.form.get('binary')
  analyzers[ns].forgot(wl, binary)
  return "Removed"

@app.route('/deploy_policy', methods=['POST'])
def deploy_policy():
  ns = request.form.get('ns')
  wl = request.form.get('wl')
  analyzers[ns].updatePolicy(wl)
  return redirect(url_for('home'))

@app.route('/remove_policy', methods=['POST'])
def remove_policy():
  ns = request.form.get('ns')
  wl = request.form.get('wl')
  analyzers[ns].deletePolicy(wl)
  return redirect(url_for('home'))

@app.route("/show_policy/<ns>/<wl>")
def get_policy(ns, wl):
  return yaml.dump([analyzers[ns].generatePolicy(wl)])

@app.route("/events/<ns>")
def get_events(ns):
  return jsonify(analyzers[ns].getEvents())

app.run(host="0.0.0.0", port=5000, debug = True)
