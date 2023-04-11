from maat import *
import logging
import time

NUM_SOLUTIONS = 10
snapshot_next = False

logger = logging.getLogger(__name__)


def match_byte(probing_results, i):
    ref = probing_results[0][i]
    return all(map(lambda m: m[i] == ref, probing_results))


def extract_predicate(results):
    predicate = dict()
    for i in range(len(results[0])):
        if match_byte(results, i):
            predicate[str(i)] = results[0][i]
    return predicate


class QueryRunner:
    def __init__(self, file, callsites_to_monitor, rec_addr=None, send_addr=None, socket_address=None):
        # Flag telling whether we should take a snapshot on the next symbolic branch
        snapshot_next = True

        ## Callback to be executed on every symbolic branch
        def path_cb(m: MaatEngine):
            global snapshot_next
            if snapshot_next:
                m.take_snapshot()
            # We can skip only one branch when we just inverted it, but then
            # we want to take snapshots for the next ones
            snapshot_next = True


        self.file = file
        self.project = MaatEngine(ARCH.X64, OS.LINUX)
        args = [self.project.vars.new_concolic_buffer("input", b'a' * 100, 100)]
        self.project.load(file, BIN.ELF64, args=args, base=0x04000000,
                          libdirs=['/Users/lunakarayanni/Desktop/9th/project/PISE/PISEServer/pise/libs/libc.so.6',
                                   '/Users/lunakarayanni/Desktop/9th/project/PISE/PISEServer/pise/libs/ld-linux-x86'
                                   '-64.so.2'])
        self.project.hooks.add(EVENT.PATH, WHEN.BEFORE, name="path", callbacks=[path_cb])
        self.mode = None
        self.callsites_to_monitor = callsites_to_monitor
        self.rec_addr = rec_addr
        self.send_addr = send_addr
        self.socket_addr = socket_address
        self.set_membership_hooks()
        # self.cache = SimulationCache()
        # self.probing_cache = ProbingCache()

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(self.project)
        self.mode = 'membership'

    def membership_step_by_step(self, inputs):
        logger.info('Performing membership, step by step')
        global snapshot_next
        global position
        position = -1
        answer = False
        deadend = False
        ms_time = 0
        # We keep trying new paths as long as execution is stopped by reaching
        # send/receive address
        t = time.process_time_ns()
        while not deadend and self.project.run() == STOP.HOOK:
            if self.project.info.addr == self.socket_addr:
                continue
            position = position + 1
            if position == len(inputs):
                # the word belongs to the language
                ms_time = max(time.process_time_ns() - t, ms_time)
                pt_time = time.process_time_ns()
                total_prob_time = 0

                # probing
                logger.info('Membership is true! - probing')
                results = []
                while self.project.run() == STOP.HOOK:
                    if self.project.info.addr == self.socket_addr:
                        continue
                    if self.project.info.addr == self.send_addr:
                        new_msg_value = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx)
                        message_list = []
                        for i in range(NUM_SOLUTIONS):
                            message_list.append(new_msg_value)
                            s = Solver()
                            for c in self.project.path.constraints():
                                s.add(c)
                            new_msg_constraint = Constraint.__ne__(
                                self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx), new_msg_value)
                            s.add(new_msg_constraint)
                            if not s.check():
                                break
                            else:
                                self.project.vars.update_from(s.get_model())
                                while self.project.run() == STOP.HOOK:
                                    if self.project.info.addr != self.socket_addr:
                                        new_msg_value = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx)
                                        break

                        # Find predicate of all the msgs
                        predicate = extract_predicate(message_list)
                        # Create solver and add constraint to common msg
                        s = Solver()
                        for c in self.project.path.constraints():
                            s.add(c)
                        for byte_num in predicate:
                            if predicate[byte_num] is not None:
                                byte_constraint = Constraint.__ne__(self.project.mem.read(self.project.cpu.rsi,
                                                                                          self.project.cpu.edx).as_int().to_bytes()[
                                                                        byte_num], predicate[byte_num])
                                s.add(byte_constraint)

                        results.extend(message_list)
                        # Check if we can get another new msg
                        if s.check():
                            # If so continue
                            self.project.vars.update_from(s.get_model())
                        else:
                            # Otherwise, break and finish
                            break

                    if self.project.info.addr == self.rec_addr:
                        self.project.mem.make_concolic(self.project.cpu.rsi.as_int(), 1, self.project.cpu.edx.as_int(),
                                                       "buf")
                        while self.project.run() == STOP.HOOK:
                            if self.project.info.addr == self.socket_addr:
                                continue
                            if self.project.info.addr == self.send_addr:
                                # check
                                new_msg_value = self.project.vars.get("buf")
                                message_list = []
                                for i in range(NUM_SOLUTIONS):
                                    message_list.append(new_msg_value)
                                    s = Solver()
                                    for c in self.project.path.constraints():
                                        s.add(c)
                                    new_msg_constraint = Constraint.__ne__(self.project.vars.get("buf"), new_msg_value)
                                    s.add(new_msg_constraint)
                                    if s.check():
                                        break
                                    else:
                                        self.project.vars.update_from(s.get_model())
                                        while self.project.run() == STOP.HOOK:
                                            if self.project.info.addr != self.socket_addr:
                                                new_msg_value = self.project.vars.get("buf")
                                                break

                                # Find predicate of all the msgs
                                predicate = extract_predicate(message_list)
                                # Create solver and add constraint to common msg
                                s = Solver()
                                for c in self.project.path.constraints():
                                    s.add(c)
                                for byte_num in predicate:
                                    if predicate[byte_num] is not None:
                                        byte_constraint = Constraint.__ne__(
                                            self.project.vars.get("buf").to_bytes()[byte_num], predicate[byte_num])
                                        s.add(byte_constraint)

                                results.extend(message_list)
                                # Check if we can get another new msg
                                if s.check():
                                    # If so continue
                                    self.project.vars.update_from(s.get_model())
                                else:
                                    # Otherwise, break and finish
                                    break

                total_prob_time = total_prob_time + (time.process_time_ns() - pt_time)
                position = position - 1
                answer = True
                break
            logger.info("Now at position %d" % position)
            # If we found the path for a send/receive message,
            # we have to check if we sent/received the message we're
            # expecting according to the input.

            if self.project.info.addr == self.rec_addr or self.project.info.addr == self.send_addr:
                expected_msg_predicate = inputs[position]
                msg_bytes = bytearray(b'')
                msg = 0
                if self.project.info.addr == self.rec_addr:
                    for i, pred in enumerate(expected_msg_predicate):
                        if pred is not None:
                            msg_bytes.append(pred)
                        else:
                            msg_bytes.append(1)
                    msg_bytes = bytes(msg_bytes)
                    msg = int.from_bytes(msg_bytes, 'big')
                if self.project.info.addr == self.send_addr:
                    msg = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx).as_int()
                    length = self.project.mem.read(self.project.cpu.edx, 8).as_int()
                    msg_bytes = msg.to_bytes(length, 'big')
                is_expected_msg = True
                for i, pred in enumerate(expected_msg_predicate):
                    if pred is not None and pred != msg_bytes[i]:
                        logger.info('The message we received/sent is not the one we are expecting')
                        logger.debug(
                            'The received/send message is %d and the one we are expecting (predicate) is %d' % (
                                msg, expected_msg_predicate))
                        logger.debug('Different at the %d th byte, expected %d != got %d' % (
                            i, pred, msg_bytes[i]))
                        is_expected_msg = False
                        break

                if is_expected_msg:
                    continue

            # Otherwise, restore previous snapshots until we find a branch condition
            # that can successfully be inverted to explore a new path
            while True:
                logger.info("Retracing steps")
                position = position - 1
                if position == -1:
                    deadend = True
                    break
                # Restore latest snapshot. This brings us back to the last
                # symbolic branch that was taken
                self.project.restore_snapshot(remove=True)
                # Use the solver to invert the branch condition, and find an
                # input that takes the other path
                s = Solver()
                # We start by adding all constraints that led to the current path.
                # Those constraints need to be preserved to ensure that the new input
                # we compute will still reach the current branch.
                # Since the snapshots are taken *before* branches are resolved,
                # m.path.constraints() doesn't contain the current branch as a constraint.
                for c in self.project.path.constraints():
                    s.add(c)
                if self.project.info.branch.taken:
                    # If branch was previously taken, we negate the branch condition
                    # so that this time it is not taken
                    s.add(self.project.info.branch.cond.invert())
                else:
                    # If the branch was not previously taken, we solve the branch condition
                    # so that this time it is taken
                    s.add(self.project.info.branch.cond)
                # If the solver found a model that inverts the current branch, apply this model
                # to the current symbolic variables context and continue exploring the next path!
                if s.check():
                    self.project.vars.update_from(s.get_model())
                    # When successfully inverting a branch, we set snapshot_next to False. We do
                    # this to avoid taking yet another snapshot of the current branch when
                    # resuming execution. We just inverted the branch, which means that one of
                    # both possibilities (taken and not taken) has been explored already, and
                    # that the other will get explored now. So there is no need to take a
                    # snapshot to go back to that particular branch.
                    snapshot_next = False
                    break

        ms_time = time.process_time_ns() - t
        if not answer:
            logger.debug("the membership query resulted in False")
            return False, None, ms_time, None, None
        else:
            logger.debug("the membership query resulted in True")
            return True, results, ms_time, None, total_prob_time
