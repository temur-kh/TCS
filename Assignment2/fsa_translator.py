import re

__ERROR = "Error:"
__E1 = "E1: A state '{}' is not in set of states"  # __is_empty_set
__E2 = "E2: Some states are disjoint"  # __has_disjoint_states
__E3 = "E3: A transition '{}' is not represented in the alphabet"  # __has_not_present_transitions
__E4 = "E4: Initial state is not defined"  # check_init_states
__E5 = "E5: Input file is malformed"  # is_malformed
__E6 = "E6: FSA is nondeterministic"  # __is_nondeterministic

__EPS = "eps"
__EMPTY_SET = "{}"
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
    :return: a dictionary of transitions in form {state: {alpha: [states]}}
    """
    trans_map = {in_st: {tr: [] for tr in alpha} for in_st in states}
    for tup in trans:
        trans_map[tup[0]][tup[1]].append(tup[2])
    return trans_map


def __create_in_trans_map(states, trans):
    """
    Create a graph of transitions in the form of a dictionary
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: a dictionary of transitions in form {state: {state: [alphas]}}
    """
    trans_map = {in_st: {out_st: [] for out_st in states} for in_st in states}
    for tup in trans:
        trans_map[tup[0]][tup[2]].append(tup[1])
    for in_st, out_st in zip(states, states):
        trans_map[in_st][out_st].sort()
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
    if trans != [""] and len([tr for tr in trans if len(tr) != 3 or not re.match("^[A-Za-z0-9]+$", tr[0])
                                                    or not re.match("[A-Za-z0-9_]+$", tr[1])
                                                    or not re.match("^[A-Za-z0-9]+$", tr[2])]):
        return __IS_MALFORMED
    return not __IS_MALFORMED


def __get_initial_regexes(states, trans):
    """
    Get the initial regular expressions
    :param states: a list of states defined in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: a list with regexes corresponding to the in_state and out_state
    """
    in_trans = __create_in_trans_map(states, trans)
    regexes = {out_st: {in_st: None for in_st in states} for out_st in states}
    # suppose checked with __is_nondeterministic() beforehand
    for out_st in states:
        for in_st in states:

            if out_st == in_st:
                regexes[out_st][in_st] = '|'.join(in_trans[out_st][in_st] + [__EPS])
            elif len(in_trans[out_st][in_st]) == 0:
                regexes[out_st][in_st] = __EMPTY_SET
            else:
                regexes[out_st][in_st] = '|'.join(in_trans[out_st][in_st])
    return regexes


def __regex_creator(states, init_state, fin_states, trans):
    """
    Create the RegExp from the FSA
    :param states: a list of states defined in the FSA
    :param init_state: a list containing an initial state
    :param fin_states: a list containing accepting states in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: string of the RegExp
    """
    # r(k, i, j) = (r(k-1, i, k))(r(k-1, k, k))*(r(k-1, k, j))|(r(k-1, i, j))
    shift = 1
    r = [{out_st: {in_st: None for in_st in states} for out_st in states} for _ in range(len(states) + shift)]
    r[-1 + shift] = __get_initial_regexes(states, trans)
    for k in range(len(states)):
        for i_st in states:
            for j_st in states:
                k_st = states[k]
                r[k + shift][i_st][j_st] = '(' + r[k + shift - 1][i_st][k_st] + \
                                           ')(' + r[k + shift - 1][k_st][k_st] + \
                                           ')*(' + r[k + shift - 1][k_st][j_st] + \
                                           ')|(' + r[k + shift - 1][i_st][j_st] + ')'
    # suppose checked with __is_malformed() beforehand
    res = '|'.join([r[-1][init_st][fin_st] for init_st in init_state for fin_st in fin_states])
    if res == '':
        res = __EMPTY_SET
    return res


def translate_fsa(states, alpha, init_state, fin_states, trans):
    """
    Translate the FSA to the Regular Expression represented by parameters:
    :param states: a list of states defined in the FSA
    :param alpha: a list of alphabet used in transitions of the FSA
    :param init_state: a list containing an initial state
    :param fin_states: a list containing accepting states in the FSA
    :param trans: a list of transitions of the form tuple(s1>a>s2) where s1 and s2 are states, and a is an alpha
    :return: result of translating the FSA
    """
    # Errors
    if __has_states_out_set(states, init_state, fin_states, trans):
        res = __ERROR
        for state in __get_states_out_set(states, init_state, fin_states, trans):
            res += "\n" + __E1.format(state)
        return res
    elif __has_disjoint_states(states, trans):
        return __ERROR + "\n" + __E2
    elif __has_not_present_transitions(alpha, trans):
        res = __ERROR
        for state in __get_not_present_transitions(alpha, trans):
            res += "\n" + __E3.format(state)
        return res
    elif __is_empty_set(init_state):
        return __ERROR + "\n" + __E4
    out_trans = __create_out_trans_map(states, alpha, trans)
    if __is_nondeterministic(out_trans):
        return __ERROR + "\n" + __E6

    res = __regex_creator(states, init_state, fin_states, trans)

    return res
