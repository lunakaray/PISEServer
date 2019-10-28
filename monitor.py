#!/usr/bin/env python
import copy
import random

import angr
import membership
import probe
from inference_server import MessageTypeSymbol


def match_byte(probing_results, i):
    ref = probing_results[0][i]
    return all(map(lambda m: m[i] == ref, probing_results))


class QueryRunner:
    def __init__(self):
        self.project = angr.Project('client')

    def run_membership_query(self, inputs):
        self.project.hook_symbol('send', membership.MonitorHook(mode='send'))
        self.project.hook_symbol('read', membership.MonitorHook(mode='read'))
        entry_state = self.project.factory.entry_state()
        entry_state.register_plugin('monitor', membership.MonitorStatePlugin(inputs))
        sm = self.project.factory.simulation_manager(entry_state)
        ret = sm.run(until=lambda sm: any(map(lambda state: state.monitor.is_done(), sm.active + sm.deadended)))
        # sm.move(from_stash='deadended', to_stash='monitored', filter_func=lambda s: s.monitor.is_done())
        if any(map(lambda state: state.monitor.is_done(), sm.active + sm.deadended)):
            return b'True'

        return b'False'

        # for _ in sm.monitored:
        #     return b'True'
        #
        # return b'False'

    def run_probe_query(self, prefix, alphabet):
        self.project.hook_symbol('send', probe.ProbeHook(mode='send'))
        self.project.hook_symbol('read', probe.ProbeHook(mode='read'))
        entry_state = self.project.factory.entry_state()
        entry_state.register_plugin('probe', probe.ProbeStatePlugin(prefix, alphabet))
        sm = self.project.factory.simulation_manager(entry_state)
        sm.run(until=lambda simgr: all(map(lambda state: state.probe.done_probing, simgr.active)))

        new_symbols = []

        for s in sm.active:
            new_symbols.append(self.process_new_symbol(s.probe.probing_results, s.probe.probing_result_type))

        for s in sm.deadended:
            if s.probe.done_probing:
                new_symbols.append(self.process_new_symbol(s.probe.probing_results, s.probe.probing_result_type))

        return new_symbols

    @staticmethod
    def process_new_symbol(probing_results, probing_result_type):
        predicate = dict()
        name = ''
        for i in range(len(probing_results[0])):
            if match_byte(probing_results, i):
                predicate[str(i)] = probing_results[0][i]
                if probing_results[0][i] != 0:
                    name = name + chr(probing_results[0][i])
        return MessageTypeSymbol(probing_result_type, name, predicate)

