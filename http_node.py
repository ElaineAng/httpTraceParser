class HTTPNode:
    __slots__ = ['__rid', '__req', '__res', '__frame']
    def __init__(self, fn=None):
        self.__rid = None
        self.__req = False
        self.__res = False
        self.__frame = fn

    def set_rid(self, rid):
        self.__rid = rid

    def get_rid(self):
        return self.__rid

    def set_req(self):
        self.__req = True

    def set_res(self):
        self.__res = True

    def is_req(self):
        return self.__req

    def is_res(self):
        return self.__res

    def set_frame(self, num):
        self.__frame = num

    def get_frame(self):
        return self.__frame
