class Buffer:
  """_summary_
  Circular buffer to store data using fixed amount of memory
  """

  def __init__(self, size):
    print("new buffer created")
    self.data = [None for i in range(size)]

  def append(self, x):
    self.data.pop(0)
    self.data.append(x)

  def get(self):
    return self.data

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
    #print("Adding %s for %s:\n%s" % (value, key, self), file=sys.stderr)
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

class DaemonSetNotfound(Exception):

  def __init__(self, ds):
    self.ds = ds

  def __str__(self):
    return "DaemonSet not Found: %s" % self.ds

class StatefulSetNotfound(Exception):

  def __init__(self, sts):
    self.sts = sts

  def __str__(self):
    return "StatefulSet not Found: %s" % self.sts

class NotImplemented(Exception):

  def __init__(self, msg):
    self.msg = msg

  def __str__(self):
    return "Not implemented: %s" % self.msg
