from maat import *
import logging
import time
NUM_SOLUTIONS = 10

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
    def __init__(self, file, callsites_to_monitor, rec_addr=None, send_addr=None):
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

        ## Exploration hooks

        self.file = file
        self.project = MaatEngine(ARCH.X64, OS.LINUX)
        self.args = [self.project.vars.new_concolic_buffer("input", b'a'*INPUT_LEN, INPUT_LEN)]
        self.project.load(file, BIN.ELF64, args=args, libdirs=["."])
        self.project.hooks.add(EVENT.PATH, WHEN.BEFORE, name="path", callbacks=[path_cb])
        self.mode = None
        self.callsites_to_monitor = callsites_to_monitor
        self.rec_addr = rec_addr
        self.send_addr = send_addr
        self.set_membership_hooks()
        #self.cache = SimulationCache()
        #self.probing_cache = ProbingCache()

    def set_membership_hooks(self):
        if self.mode == 'membership':
            return
        logger.info('Setting hooks')
        for callsite in self.callsites_to_monitor:
            callsite.set_hook(m)
        self.mode = 'membership'

    def membership_step_by_step(inputs):
        logger.info('Performing membership, step by step')
        global snapshot_next
        global position = -1
        answer = False
        deadend = False
        skip_verification = False
        # We keep trying new paths as long as execution is stopped by reaching
        # send/receive address
        t = time.process_time_ns()
        while not deadend and self.project.run() == STOP.HOOK:
            position = position + 1
            if position == len(inputs):
                # the word belongs to the language
                ms_time = max(time.process_time_ns() - t, ms_time)
                pt_time = time.process_time_ns()
                total_prob_time = 0

                # probing
                logger.info('Membership is true - probing')
                results = []
                while self.project.run() == STOP.HOOK:
                    if self.project.info.addr == self.send_addr:
                        new_msg_value = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx)
                        message_list = []
                        for i in range(NUM_SOLUTIONS):
                            message_list.append(new_msg_value)
                            s = Solver()
                            for c in self.project.path.constraints():
                                s.add(c)
                            new_msg_constraint = Constraint.__ne__(self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx), new_msg_value)
                            s.add(new_msg_constraint)
                            if not s.check():
                                break
                            else:
                                self.project.vars.update_from(s.get_model())
                                while self.project.run() == STOP.HOOK:
                                    new_msg_value = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx)

                        # Find predicate of all the msgs
                        predicate = extract_predicate(message_list)
                        # Create solver and add constraint to common msg
                        s = Solver()
                        for c in self.project.path.constraints():
                            s.add(c)
                        for byte_num in predicate:
                            if predicate[byte_num] is not None:
                                byte_constraint = Constraint.__ne__(self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx).as_int().to_bytes()[byte_num], predicate[byte_num])
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

                        # Need to complete
                total_prob_time = total_prob_time + (time.process_time_ns() - pt_time)
                return results

                position = position - 1
                skip_verification = True
                answer = True
                break
            logger.info("Now at position %d" % position)
            # If we found the path for a send/receive message,
            # we have to check if we sent/recieved the message we're
            # expecting accorrding to the input.

            if not skip_verification and (self.project.info.addr == self.rec_addr or self.project.info.addr == self.send_addr):
                msg = self.project.mem.read(self.project.cpu.rsi, self.project.cpu.edx).as_int()
                length = self.project.mem.read(self.project.cpu.edx, 8).as_int()
                msg_bytes = msg.to_bytes(length, 'big')
                expected_msg_predicate = inputs[position]
                is_expected_msg = True
                for i in enumerate(expected_msg_predicate):
                    if expected_msg_predicate[i] is not None and expected_msg_predicate[i] != msg_bytes[i]
                        logger.info('The message we received/sent is not the one we are expecting')
                        logger.debug('The received/send message is %d and the one we are expecting (predicate) is %d' % (msg, expected_msg_predicate))
                        logger.debug('Different at the %d th byte,  expected %d != got %d' % (i, expected_msg_predicate[i], msg_bytes[i]))
                        is_expected_msg = False
                        break
                if is_expected_msg:
                    continue

            # Otherwise, restore previous snapshots until we find a branch condition
            # that can successfuly be inverted to explore a new path
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
                    skip_verification = False
                    break

        ms_time = time.process_time_ns() - t
        if answer == False:
            logger.debug("the membership query resulted in False")
            return False, None, ms_time, None, None
        else:
            logger.debug("the membership query resulted in True")
            return True, results, ms_time, None, total_prob_time
