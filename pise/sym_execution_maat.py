from maat import *
import logging
import time

class QueryRunner:
    def __init__(self, file, callsites_to_monitor, rec_addr=None, send_addr=None):
        # still not sure about specs
        m = MaatEngine(ARCH.X64, OS.LINUX)
        args = [
            m.vars.new_concolic_buffer("input", b'a'*INPUT_LEN, INPUT_LEN)
        ]
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
        m.hooks.add(EVENT.PATH, WHEN.BEFORE, name="path", callbacks=[path_cb])

        self.file = file
        self.project = m.load(file, BIN.ELF64, args=args, libdirs=["."])
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
        answer = None
        # We keep trying new paths as long as execution is stopped by reaching
        # SUCCESS_ADDR or FAILURE_ADDR
        t = time.process_time_ns()

        while answer is not False and self.project.run() == STOP.HOOK:
            position = position + 1
            if position == len(inputs):
                answer = True
                break
            logger.info("Now at position %d" % position)
            # If we found the path for a send/receive message,
            # we have to check if we sent/recieved the message we're
            # expecting accorrding to the input.

            if m.info.addr == self.rec_addr or m.info.addr == self.send_addr:
                msg = m.cpu.rsi.as_int()
                length = m.cpu.edx.as_int()
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
                    answer = False
                    break
                # Restore latest snapshot. This brings us back to the last
                # symbolic branch that was taken
                m.restore_snapshot(remove=True)
                # Use the solver to invert the branch condition, and find an
                # input that takes the other path
                s = Solver()
                # We start by adding all constraints that led to the current path.
                # Those constraints need to be preserved to ensure that the new input
                # we compute will still reach the current branch.
                # Since the snapshots are taken *before* branches are resolved,
                # m.path.constraints() doesn't contain the current branch as a constraint.
                for c in m.path.constraints():
                    s.add(c)
                if m.info.branch.taken:
                    # If branch was previously taken, we negate the branch condition
                    # so that this time it is not taken
                    s.add(m.info.branch.cond.invert())
                else:
                    # If the branch was not previously taken, we solve the branch condition
                    # so that this time it is taken
                    s.add(m.info.branch.cond)
                # If the solver found a model that inverts the current branch, apply this model
                # to the current symbolic variables context and continue exploring the next path!
                if s.check():
                    m.vars.update_from(s.get_model())
                    # When successfully inverting a branch, we set snapshot_next to False. We do
                    # this to avoid taking yet another snapshot of the current branch when
                    # resuming execution. We just inverted the branch, which means that one of
                    # both possibilities (taken and not taken) has been explored already, and
                    # that the other will get explored now. So there is no need to take a
                    # snapshot to go back to that particular branch.
                    snapshot_next = False
                    break

        ms_time = time.process_time_ns() - t
        if answer == False:
            logger.debug("the membership query resulted in False")
            # the membership query resulted False
            return False, None, ms_time, None, None
        # Probing phase
        logger.info('Membership is true - probing')
        t = time.process_time_ns()
        new_messages = []
        while self.project.run() == STOP.HOOK or self.project.run() == STOP.EXIT:
            if m.info.addr == self.rec_addr or m.info.addr == self.send_addr:
                msg = m.cpu.rsi
                length = m.cpu.edx
                new_messages.append(msg)
            break
        probe_time = time.process_time_ns() - t
        return True, new_messages, ms_time, 0, probe_time
