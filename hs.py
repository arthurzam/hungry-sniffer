import _hs_private

class Layer:
    def __init__(self, dict):
        self.name = dict['name']
        self.headers = dict['headers']
        self.info = dict['info']

    def __getitem__(self, index):
        if isinstance(index, str):
            return self.headers[index]
        return None

    def __str__(self):
        res = self.name + "\n"
        res += self.info + "\n"
        return res

    def __repr__(self):
        return "[{0} - {1}]".format(self.name, self.info)

class Packet:
    def __init__(self, dict):
        self.num = dict['num']
        self.isShown = dict['isShown']
        self.data = dict['data']

        self.layers = []
        for layer in dict['layers']:
            self.layers.append(Layer(layer))

    def __getitem__(self, index):
        if isinstance(index, int):
            return self.layers[index]
        if isinstance(index, str):
            for layer in self.layers:
                if layer.name == index:
                    return layer
        return None

    def __getslice__(self, slice):
        return self.layers[slice]

    def __str__(self):
        res = "#{0}\n".format(self.num + 1)
        res += "shown\n" if self.isShown else "not shown\n"
        res += self.layers[0].name
        for layer in self.layers[1:]:
            res += "-> " + layer.name
        res += "\n"
        return res

    def __repr__(self):
        return "[{0} - {1} - {2}]".format(self.num, self.isShown, [layer.name for layer in self.layers])

class AllPackets:
    def __init__(self):
        class AllPackets_iter:
            def __init__(self):
                self.current = -1

            def __next__(self):
                self.current += 1
                next = _hs_private.getPacketNum(self.current)
                if next:
                    return Packet(next)
                else:
                    raise StopIteration
        self.iter_class = AllPackets_iter

    def __len__(self):
        return _hs_private.getCountAll()

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[ii] for ii in range(*index.indices(len(self)))]
        if isinstance(index, int):
            return Packet(_hs_private.getPacketNum(index))
        return None

    def __iter__(self):
        return self.iter_class()

class ShownPackets:
    def __init__(self):
        class ShownPackets_iter:
            def __init__(self):
                self.current = -1

            def __next__(self):
                next = _hs_private.getNextShown(self.current + 1)
                if next:
                    p = Packet(next)
                    self.current = p.num
                    return p
                else:
                    raise StopIteration

        self.iter_class = ShownPackets_iter

    def __len__(self):
        return _hs_private.getCountShown()

    def __getitem__(self, index):
        if isinstance(index, int):
            return Packet(_hs_private.getNextShown(index))
        return None

    def __iter__(self):
        return self.iter_class()

all = AllPackets()
shown = ShownPackets()
