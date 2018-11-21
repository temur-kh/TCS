import re

__ERROR = "Error:"
__E1 = "E1: A state '{}' is not in set of states"  # __is_empty_set
__E2 = "E2: Some states are disjoint"  # __has_disjoint_states
__E3 = "E3: A transition '{}' is not represented in the alphabet"  # __has_not_present_transitions
__E4 = "E4: Initial state is not defined"  # check_init_states
__E5 = "E5: Input file is malformed"  # is_malformed

__WARNING = "Warning:"
__W1 = "W1: Accepting state is not defined"  # __is_empty_set
__W2 = "W2: Some states are not reachable from initial state"  # __has_not_reachable_states
__W3 = "W3: FSA is nondeterministic"  # __is_nondeterministic

__FSA_COMPLETE = "FSA is complete"  # __is_complete
__FSA_INCOMPLETE = "FSA is incomplete"  # not __is_complete

__NUMBER_OF_LINES = 5
__IS_MALFORMED = True


def __dfs(cur, path, visited):
    """
    Depth-first search in a graph
    :param cur: a current node in the graph
    :param path: a dictionary of transitions in the graph
    :param visited: a dictionary of boolean variables to check visits to the nodes
    :return: 0
    """
    for state in path[cur]:
        if not visited[state]:
            visited[state] = True
            __dfs(state, path, visited)
    pass


def __has_not_reachable_states(states, trans, init_state):
    """
    Check if the FSA has not reachable states
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :param init_state: a list containing an initial state
    :return: True if the FSA has not reachable states else False
    """
    path = {state: set() for state in states}
    visited = {state: False for state in states}
    for tup in trans:
        path[tup[0]].add(tup[2])
    for state in init_state:
        if not visited[state]:
            visited[state] = True
            __dfs(state, path, visited)
    return len([None for state in visited.keys() if not visited[state]])


def __has_disjoint_states(states, trans):
    """
    Check if the FSA has disjoint states using counting of graph components
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: True if the FSA has disjoint states else False
    """
    cnt_components = 0
    path = {state: set() for state in states}
    visited = {state: False for state in states}
    for tup in trans:
        path[tup[0]].add(tup[2])
        path[tup[2]].add(tup[0])
    for state in path.keys():
        if not visited[state]:
            visited[state] = True
            __dfs(state, path, visited)
            cnt_components += 1
    return cnt_components > 1


def __create_out_trans_map(states, alpha, trans):
    """
    Create a graph of transitions in the form of a dictionary
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: a dictionary of transitions
    """
    trans_map = {in_st: {tr: [] for tr in alpha} for in_st in states}
    for tup in trans:
        trans_map[tup[0]][tup[1]].append(tup[2])
    return trans_map


def __get_not_present_transitions(alpha, trans):
    """
    Return a set of transitions undefined in the alphabet
    :param alpha: a list of alphabet used in transitions of the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: a set of undefined transitions
    """
    return [tup[1] for tup in trans if tup[1] not in alpha]


def __has_not_present_transitions(alpha, trans):
    """
    Check if the transitions list contains transitions undefined in the list of alphabet
    :param alpha: a list of alphabet used in transitions of the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: True if there are undefined transitions else False
    """
    return len(__get_not_present_transitions(alpha, trans))


def __get_states_out_set(states, init_state, fin_states, trans):
    """
    Return a set of states of the initial state list, final states list and the list of transitions
    that are not defined in the states list
    :param states: a list of states defined in the FSA
    :param init_state: a list containing an initial state
    :param fin_states: a list containing accepting states in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: a set of undefined states
    """
    return set([tup[0] for tup in trans if tup[0] not in states] +
               [tup[2] for tup in trans if tup[2] not in states] +
               [state for state in init_state if state not in states] +
               [state for state in fin_states if state not in states])


def __has_states_out_set(states, init_state, fin_states, trans):
    """
    Check if the initial state list, final states list and the list of transitions
    have some states not defined in the list of states
    :param states: a list of states defined in the FSA
    :param init_state: a list containing an initial state
    :param fin_states: a list containing accepting states in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: True if there undefined states else False
    """
    return len(__get_states_out_set(states, init_state, fin_states, trans))


def __is_nondeterministic(out_trans):
    """
    Check if the FSA is nondeterministic
    :param out_trans: a dictionary of transitions
    :return: True if the FSA is nondeterministic else False
    """
    return len([None for key1 in out_trans for key2 in out_trans[key1] if len(out_trans[key1][key2]) > 1])


def __is_complete(alpha, out_trans):
    """
    Check if the FSA is complete
    :param alpha: a list of alphabet used in transitions of the FSA
    :param out_trans: a dictionary of transitions
    :return: True if the FSA is complete else False
    """
    return not len([None for key1 in out_trans for key2 in out_trans[key1] if len(out_trans[key1][key2]) == 0])


def __is_empty_set(collection):
    """
    Check if the set is empty
    :param collection: a set to be checked
    :return: True if the set is empty else False
    """
    return not len(collection)


def get_malformed_error():
    """
    Get an error log of malformed input
    :return: log of an error
    """
    return __ERROR + "\n" + __E5


def is_malformed(lines):
    """
    Check the input file lines for being malformed
    :param lines: lines of the file
    :return: True if the FSA is malformed else False
    """
    lines = lines[:]
    if len(lines) != __NUMBER_OF_LINES:
        return __IS_MALFORMED
    states, alpha, init_state, fin_states, trans = tuple(lines)
    if not re.match("^states={[A-Za-z0-9,]*}$", states) or not re.match("^alpha={[A-Za-z0-9_,]*}$", alpha) \
            or not re.match("^init.st={[A-Za-z0-9]*}$", init_state) \
            or not re.match("^fin.st={[A-Za-z0-9,]*}$", fin_states) \
            or not re.match("^trans={[A-Za-z0-9,_>]*}$", trans):
        return __IS_MALFORMED
    states = states.split("=")[1][1:-1].split(",")
    if states != [""] and len([st for st in states if not re.match("^[A-Za-z0-9]+$", st)]):
        return __IS_MALFORMED
    alpha = alpha.split("=")[1][1:-1].split(",")
    if alpha != [""] and len([ch for ch in alpha if not re.match("^[A-Za-z0-9_]+$", ch)]):
        return __IS_MALFORMED
    fin_states = fin_states.split("=")[1][1:-1].split(",")
    if fin_states != [""] and len([fst for fst in fin_states if not re.match("^[A-Za-z0-9]+$", fst)]):
        return __IS_MALFORMED
    trans = [tr.split(">") for tr in trans.split("=")[1][1:-1].split(",")]
    if trans != [""] and len([tr for tr in trans if len(tr) != 3 or
                                                    not re.match("^[A-Za-z0-9]+$", tr[0]) or
                                                    not re.match("[A-Za-z0-9_]+$", tr[1]) or
                                                    not re.match("^[A-Za-z0-9]+$", tr[2])]):
        return __IS_MALFORMED
    return not __IS_MALFORMED


def validate_fsa(states, alpha, init_state, fin_states, trans):
    """
    Validate the FSA represented by parameters:
    :param states: a list of states defined in the FSA
    :param alpha: a list of alphabet used in transitions of the FSA
    :param init_state: a list containing an initial state
    :param fin_states: a list containing accepting states in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: result of validating the FSA
    """
    # Errors
    if __has_states_out_set(states, init_state, fin_states, trans):
        res = __ERROR
        for state in __get_states_out_set(states, init_state, fin_states, trans):
            res += "\n" + __E1.format(state)
        return res
    elif __has_disjoint_states(states, trans):
        res = __ERROR + "\n" + __E2
        return res
    elif __has_not_present_transitions(alpha, trans):
        res = __ERROR
        for state in __get_not_present_transitions(alpha, trans):
            res += "\n" + __E3.format(state)
        return res
    elif __is_empty_set(init_state):
        res = __ERROR + "\n" + __E4
        return res

    res = ""
    # Completeness
    out_trans = __create_out_trans_map(states, alpha, trans)
    res += __FSA_COMPLETE if __is_complete(alpha, out_trans) else __FSA_INCOMPLETE
    has_warning = False

    # Warning 1
    if __is_empty_set(fin_states):
        if not has_warning:
            res += "\n" + __WARNING
            has_warning = True
        res += "\n" + __W1
    # Warning 2
    if __has_not_reachable_states(states, trans, init_state):
        if not has_warning:
            res += "\n" + __WARNING
            has_warning = True
        res += "\n" + __W2
    # Warning 3
    if __is_nondeterministic(out_trans):
        if not has_warning:
            res += "\n" + __WARNING
        res += "\n" + __W3

    return res
