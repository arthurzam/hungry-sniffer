"""
    Copyright (c) 2015 Zamarin Arthur

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the Software
    is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
    OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
import _hs_private

class AllPackets:
    def __init__(self):
        class AllPackets_iter:
            def __init__(self):
                self.current = -1

            def __next__(self):
                self.current += 1
                if next:
                    return Packet(self.current)
                else:
                    raise StopIteration
        self.iter_class = AllPackets_iter

    def __len__(self):
        return _hs_private.getCountAll()

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[ii] for ii in range(*index.indices(len(self)))]
        if isinstance(index, int):
            if index >= 0:
                return Packet(index)
            else:
                return Packet(len(self) + index)
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
            if index >= 0:
                return Packet(_hs_private.getNextShown(index))
        return None

    def __iter__(self):
        return self.iter_class()

all = AllPackets()
shown = ShownPackets()

def addPacket(data):
    _hs_private.savePacket(-1, data)
