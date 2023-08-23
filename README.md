# policy builder

This tool is a proof-of-concept tool, which profiles apps running in k8s,
and issues TracingPolicies allowing only processes run under the profiles.

It parses output from Tetragon and creates Cilium TracingPolicies, which
enable only , per namespace, per workloads, some whitelisted processes.


## requirements
* python3
* pip

## install

* git clone
* pip install -r /path/to/requirements.txt 

## run example


### help

```bash
>> python3 builder.py -h
usage: builder.py [-h] [--file FILE] [--eol-parser EOL_PARSER] [--output OUTPUT]

Process input from stdin or a file.

options:
  -h, --help            show this help message and exit
  --file FILE           path to input file
  --eol-parser EOL_PARSER
                        use EOL parser instead of braces count based parser
  --output OUTPUT       path to input file

```

### parse from file

```bash

>> python3 -m builder --file my_tetragon_dump.txt --output test.yaml

# events parsed
# EventProcessExec(ns='thanos', wl='thanos-bucketweb', bin='/bin/oauth2-proxy')
# EventProcessExec(ns='thanos', wl='thanos-compactor', bin='/bin/thanos')
# EventProcessExec(ns='thanos', wl='thanos-compactor', bin='/bin/test2')

>> head test.yaml

---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "policy-thanos-bucketweb-whitelist"
  namespace: "thanos"
spec:
  tracepoints:
    - subsystem: "raw_syscalls"


```

### parse from tetragon stdout 

stop w/ SIGINT, which -depending on your args- triggers file creation or prints on stdout

```bash
>> kubectl logs --follow daemonset/tetragon -n tetragon -c export-stdout | python3 -m builder --output policies.yaml
Found 5 pods, using pod/tetragon-vz57z
^Cwriting to file:  policies.yaml

```
