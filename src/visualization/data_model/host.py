from benedict.dicts import benedict

class host:
    def __init__(self, data=None) -> host:
        if not data: return
        self._data = data

    def _update(self, key_path, data=None):
        self._data[key]  = value

    def get(self, key) -> [] or {} or None:
        if subkey in self._data:
            return self._data[key]

    def get_host_names(self) -> [] or None:
        subkey='names'
        return self.get(subkey)

    def get_mac(self) -> str or None:
        subkey='MAC.src'
        return self.get(subkey)

