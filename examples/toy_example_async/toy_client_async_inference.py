import logging

import angr
from angr import SimProcedure

from pise import sym_execution, server, hooks

logger = logging.getLogger(__name__)


# TODO: make this work
class ToySendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        # p.hook(0x1180, hooks.SendHook(self))
        p.hook_symbol('sendString', hooks.SendHook(self))

    def extract_arguments(self, hooker):
        buffer = hooker.state.regs.rdi
        length = hooker.inline_call(angr.SIM_PROCEDURES['libc']['strlen'], buffer).ret_expr
        return buffer, length


class ToyAsyncRecvHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('recvAux', RecvHook())

    def extract_arguments(self, hooker):
        length = hooker.state.regs.edx
        buffer = hooker.state.regs.rdi
        return buffer, length


class RecvHook(SimProcedure):
    IS_FUNCTION = True
    local_vars = ()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def run(self):
        buffer_arg = self.inline_call(angr.SIM_PROCEDURES['libc']['malloc'], 0x40).ret_expr
        length = 0x40
        logger.debug('Async recv hook, making up some message')
        self.state.query.handle_recv(buffer_arg, length)
        addr = self.state.project.loader.find_symbol('onMessageReceived').rebased_addr
        self.call(addr=addr, args=(buffer_arg, length), continue_at='cont')

    def cont(self):
        return self.state.regs.al


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('toy_example_async', [ToySendHook(), ToyAsyncRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
