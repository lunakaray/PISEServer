import logging
from maat import *
from pise import sym_execution_maat, server


class ToySendHook:
    def __init__(self, send_msg_add):
        self.send_msg_add = send_msg_add

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        # call_context.state.regs.rax = length
        return

    def set_hook(self, m: MaatEngine):
        m.hooks.add(EVENT.EXEC, WHEN.BEFORE, name="send", filter=self.send_msg_add)

    def extract_arguments(self, call_context):
        # length = call_context.state.regs.edx
        # buffer = call_context.state.regs.rsi
        # return buffer, length
        return


class ToyRecvHook:
    def __init__(self, recv_msg_add):
        self.recv_msg_add = recv_msg_add

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        # call_context.state.regs.rax = length
        return

    def set_hook(self, m: MaatEngine):
        m.hooks.add(EVENT.EXEC, WHEN.BEFORE, name="recv", filter=self.recv_msg_add)

    def extract_arguments(self, call_context):
        # length = call_context.state.regs.edx
        # buffer = call_context.state.regs.rsi
        # return buffer, length
        return


class ToySocketHook:
    def __init__(self, socket_add):
        self.socket_add = socket_add

    def get_return_value(self, buff, length, call_context):
        return

    def set_hook(self, m: MaatEngine):
        m.hooks.add(EVENT.EXEC, WHEN.BEFORE, name="socket", filter=self.socket_add)

    def extract_arguments(self, call_context):
        return


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_execution_maat.QueryRunner('examples/toy_example/toy_example',
                                                  callsites_to_monitor=[ToySendHook(0x4001170), ToyRecvHook(0x4001130),
                                                                        ToySocketHook(0x4001210)], rec_addr=0x4001130,
                                                  send_addr=0x4001170, socket_address=0x4001210)
    s = server.Server(query_runner=query_runner)
    s.listen()


if __name__ == "__main__":
    main()
