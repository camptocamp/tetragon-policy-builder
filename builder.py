import yaml
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
from analyzer import BackgroundAnalyser, BackgroundFlush, BackgroundFetchEvent, NamespaceAnalyser, ExecTree

# Read pod selector to find tetragon pods
tetragon_pod_selector = os.environ.get('TETRAGON_POD_SELECTOR', 'app.kubernetes.io/instance=tetragon,app.kubernetes.io/name=tetragon')

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
analyzers : dict[str, NamespaceAnalyser] = dict()
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

@app.route('/')
def home():
  return render_template('index.html', analyzers=analyzers.copy())

@app.route('/health')
def health():
  return 'OK'

@app.route('/remove_binary', methods=['POST'])
def remove_binary():
  ns = request.form.get('ns')
  wl = request.form.get('wl')
  binary = request.form.get('binary')
  analyzers[ns].forgot(wl, binary)
  return 'Removed'

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

@app.route('/show_policy/<ns>/<wl>')
def get_policy(ns, wl):
  return yaml.dump(analyzers[ns].generatePolicy(wl))

@app.route('/workloads/<ns>')
def get_workloads(ns):
  if not ns in analyzers:
    raise KeyError("No such namespace")

  return jsonify(analyzers[ns].workloads.keys())

@app.route('/events/<ns>/<wl>')
def get_events(ns, wl):

  if not ns in analyzers:
    raise KeyError("No such namespace")

  analyzer : NamespaceAnalyser = analyzers[ns]

  if not wl in analyzer.workloads:
    raise KeyError("No such workloads")

  groups = []
  items = []
  for group_id, t in enumerate(analyzer.workloads[wl].trees):
    groups.append(t.description) # TODO create function?
    items.extend([ i | { "group": group_id} for i in t.get_json()])

  if len(items) == 0:
    return jsonify([])

  return jsonify(
    {
      'items': items,
      'groups': [{'id':i, 'content':g} for i, g in enumerate(groups)],
    }
  )

app.run(host='0.0.0.0', port=5000)
