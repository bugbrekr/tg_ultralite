import json
import msgpack
import os

class JSONDatabase:
    def __init__(self, path):
        if not os.path.isfile(path):
            if os.path.isdir(os.path.dirname("./"+path)):
                self._write(path, {})
            else:
                raise NotADirectoryError
        try:
            self._read(path)
        except json.decoder.JSONDecodeError:
            raise ValueError("Databse is not a valid JSON file")
        self.path = path
    def _read(self, path):
        with open(path, "r") as f:
            data = json.loads(f.read().strip())
        return data
    def _write(self, path, data):
        d = json.dumps(data)
        with open(path, "w") as f:
            f.write(d)
    def get(self, key):
        d = self._read(self.path)
        return d.get(key)
    def pop(self, key):
        d = self._read(self.path)
        try:
            v = d.pop(key)
        except KeyError:
            raise KeyError
        self._write(self.path, d)
        return v
    def __getitem__(self, key):
        v = self.get(key)
        if v == None:
            raise KeyError
        return v
    def __setitem__(self, key, value):
        d = self._read(self.path)
        d[key] = value
        self._write(self.path, d)
    def __delitem__(self, key):
        d = self._read(self.path)
        try:
            d.pop(key)
        except KeyError:
            return KeyError
        self._write(self.path, d)
    def __iter__(self):
        d = self._read(self.path)
        for k in d.keys():
            yield k
    def __len__(self):
        d = self._read(self.path)
        return len(d.keys())
    def __contains__(self, k):
        return k in self.keys()
    def keys(self):
        d = self._read(self.path)
        return d.keys()
    def values(self):
        d = self._read(self.path)
        return d.values()
    def items(self):
        d = self._read(self.path)
        return d.items()

class MessagePackDatabase(JSONDatabase):
    def __init__(self, path):
        if not os.path.isfile(path):
            if os.path.isdir(os.path.dirname("./"+path)):
                self._write(path, {})
            else:
                raise NotADirectoryError
        try:
            self._read(path)
        except ValueError:
            raise ValueError("Databse is not a valid MessagePack file")
        self.path = path
    def _read(self, path):
        with open(path, "rb") as f:
            rdata = f.read().strip()
        try:
            data = msgpack.loads(rdata)
        except:
            raise ValueError
        return data
    def _write(self, path, data):
        d = msgpack.dumps(data)
        with open(path, "wb") as f:
            f.write(d)