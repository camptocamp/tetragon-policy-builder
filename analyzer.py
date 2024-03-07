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
from utils import *

BUFFER_SIZE = 100

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
        return "misc"
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
      print("No owner found for {}".format(api_response.metadata))
      return (None,"misc")
      #pprint(api_response)

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
      wl = self.getWorkload(event[1])
      #print("Workload for %s/%s is %s" % (self.ns, event[1], wl))

      with self.lock:
        self.binaries.add("%s-%s" % (wl[0], wl[1]), event[2])
        self.events_tail.append(event+(wl[0], wl[1]))

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
      eventType = eventType[0]
      time = e["time"]

      # Only use process_exec events (?)
      if eventType not in ("process_exec", "process_exit"):
        return None

      # Extract metadata
      bin = e[eventType]["process"]["binary"]
      try:
        args = e[eventType]["process"]["arguments"]
      except KeyError:
        args = ""

      ns = e[eventType]["process"]["pod"]["namespace"]
      pod = e[eventType]["process"]["pod"]["name"]
      container = e[eventType]["process"]["pod"]["container"]["name"]

      return (ns, pod, bin, args, eventType, time, container)
