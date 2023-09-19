<picture>
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/camptocamp/tetragon-policy-builder/master/static/logo.png" width="200">
  <img src="https://raw.githubusercontent.com/camptocamp/tetragon-policy-builder/master/static/logo.png" width="200">
</picture>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<a href="https://github.com/camptocamp/tetragon-policy-builder/blob/master/screenshot1.png">
  <picture style="margin-left: 100px;">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/camptocamp/tetragon-policy-builder/master/screenshot2.png" height="200">
    <img src="https://raw.githubusercontent.com/camptocamp/tetragon-policy-builder/master/static/screenshot2.png" height="200">
  </picture>
</a>

# Tetragon Policy Builder

This tool is a proof-of-concept tool, which profiles apps running in k8s,
and issues TracingPolicies allowing only processes run under the profiles.

It parses output from Tetragon and creates Cilium TracingPolicies, which
enable only, per namespace, per workloads, some whitelisted processes.

[Tetragon](https://github.com/cilium/tetragon) *MUST* be running in the
kubernetes cluster with the `tetragon.enablePolicyFilter: true`
[value](https://tetragon.cilium.io/docs/reference/helm-chart/#values).

## Deploy Tetragon

Check the [Quick Start guide](https://tetragon.cilium.io/docs/getting-started/kubernetes-quickstart-guide/):

```bash
$ helm repo add cilium https://helm.cilium.io
$ helm repo update
$ helm install tetragon cilium/tetragon -n kube-system --set tetragon.enablePolicyFilter=true
```

## Deploy the policy builder

### Using helm

```bash
$ git clone https://github.com/camptocamp/tetragon-policy-builder.git
$ cd tetragon-policy-builder
$ helm install -n kube-system policy-builder helm/tetragon-policy-builder
```

Then you can open a "port-forward" to access the web UI:

```bash
kubectl port-forward -n kube-system deploy/policy-builder 5000:5000
```

and access the interface with your wen browser: [http://localhost:5000/](http://localhost:5000/)

After uninstalling with helm:

```bash
$ helm uninstall -n kube-system policy-builder
```

You will need to cleanup some configmap created by the policy builder, you can
list configmaps with:

``` bash
$ kubectl get cm -A -l generated-by=tetragon-policy-builder
```

and then delete configmap with:

```bash
$ kubectl delete cm -A -l generated-by=tetragon-policy-builder
```

## Using Docker

The docker container will need to authenticate to the kubernetes. You will need
to share the kubeconfig to the container:

```bash
$ docker run -p 5000:5000 -e KUBECONFIG=/tmp/kubeconfig -v $KUBECONFIG:/tmp/kubeconfig ghcr.io/camptocamp/tetragon-policy-builder:latest
```

Be sure to cleanup configmap created by the policy builder with:

```bash
$ kubectl delete cm -A -l generated-by=tetragon-policy-builder
```

Use you web browser to access the interface: [http://localhost:5000/](http://localhost:5000/)

## Directly on the workstation for dev purpose

```bash
$ git clone https://github.com/camptocamp/tetragon-policy-builder.git
$ cd tetragon-policy-builder
$ virtualenv venv
$ . venv/bin/activate
$ pip install -r /path/to/requirements.txt
$ python3 -m builder
```

Ensure that you have access to a kubernetes cluster:

```bash
$ kubectl cluster-info
Kubernetes control plane is running at https://e07df10a-56d2-11ee-bd90-a77949f1c0d2.sks-de-fra-1.exo.io:443
CoreDNS is running at https://e07df10a-56d2-11ee-bd90-a77949f1c0d2.sks-de-fra-1.exo.io:443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

Launch the policy builder:
```bash
python3 -m builder
```

Open the web interface: [http://localhost:5000/](http://localhost:5000/)

Be sure to cleanup configmap created by the policy builder with:

```bash
$ kubectl delete cm -A -l generated-by=tetragon-policy-builder
```
