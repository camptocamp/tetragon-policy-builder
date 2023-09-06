import re
import sys
import signal
import json
import jinja2
import argparse
from collections import defaultdict

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

def extract_workload_prefix(s):
  """Returns workload id as:

  Assumes pattern
  workload-<rs-id>-<pod-id>
  """
  match = re.match(r'^(.*?)-\d+[a-zA-Z0-9-]+$', s)
  if match:
    return match.group(1)
  else:
    # this is very try an error, but we are guessing now workload is a deamon set
    # we assume pattern workload-<pod-id>

      match = re.match(r'^(.*?)-[a-zA-Z0-9]+$', s)
      if match:
        return match.group(1)
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

class Analyzer:

  def __init__(self):
    self.event_counter = dict()
    self.ns_ls = []
    self.ps_ls = []

  def count(self, e:EventProcessExec):
    if e in self.event_counter:
      self.event_counter[e] += 1
    else:
      self.event_counter[e] = 1

  def process(self, d: dict):
      e = None

      if "process_exec" in d:
        e = EventProcessExec(
           ns  = d["process_exec"]["process"]["pod"]["namespace"],
           ctr = d["process_exec"]["process"]["pod"]["container"]["name"],
           bin = d["process_exec"]["process"]["binary"],
           wl  = extract_workload_prefix(d["process_exec"]["process"]["pod"]["name"]),
        )
      elif "process_exit" in d:
        e = EventProcessExit(
           ns  = d["process_exit"]["process"]["pod"]["namespace"],
           ctr = d["process_exit"]["process"]["pod"]["container"]["name"],
           bin = d["process_exit"]["process"]["binary"],
           wl  = extract_workload_prefix(d["process_exit"]["process"]["pod"]["name"]),
        )

      else:
         raise NotImplementedError(f"unknown event type: {d}")

      self.count(e)
      return e

  def print_stats(self):
    print(self.event_counter)

class EventProcessExit(EventProcessExec):
  pass

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
    graph[item.ns][item.wl].add(item.bin)\

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


def main():

  # cli
  parser = argparse.ArgumentParser(description="Process input from stdin or a file.")
  parser.add_argument('--file', type=str, help='path to input file')
  parser.add_argument('--eol-parser', type=str, help='use EOL parser instead of braces count based parser')
  parser.add_argument('--output', type=str, help='path to input file')
  args = parser.parse_args()

  # states
  analyzer = Analyzer()
  events = []

  # on_exit handler
  def signal_handler(sig, frame):
    if args.output:
      with open(args.output, 'w', encoding='utf-8') as f:
        print("writing to file: ", args.output)
        f.write(export_policy(events))
    else:
      print(export_policy(events))

    print("# events parsed")
    for e in events:
      print("#", e)
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
  # else read from stdin
  else:
    for line in sys.stdin:
      data = json.loads(''.join(line))
      e = analyzer.process(data)
      if e is None:
        print(f"Couldn't parse data from line {line}.")
      if e not in events:
        events.append(e)


if __name__ == "__main__":
  main()
