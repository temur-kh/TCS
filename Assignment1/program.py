from fsa_validator import *

INPUT_FILE = "fsa.txt"
OUTPUT_FILE = "result.txt"


def make_set(line):
    """
    Transform the input line into a set of strings
    :param line:  an input line
    :return: a set of strings
    """
    line = line.strip().split("=")[1][1:-1].split(",")
    if line == [""]:
        return {}
    new_set = set()
    if len(line) > 0 and ">" in line[0]:
        for item in line:
            obj = item.split(">")
            new_set.add(tuple(obj))
    else:
        new_set = set(line)
    return new_set


def main():
    """
    Main functions
    :return: 0
    """
    try:
        with open(INPUT_FILE, "r") as file:
            lines = [line.strip() for line in file.readlines()]
        if is_malformed(lines):
            raise SyntaxError("Input file is malformed!")
        states, alpha, init_state, fin_states, trans = (make_set(line) for line in lines)
        result = validate_fsa(states, alpha, init_state, fin_states, trans)
        file.close()
    except SyntaxError:
        result = get_malformed_error()
    except _ as e:
        result = "Something went wrong: " + e
    file = open(OUTPUT_FILE, "w")
    file.write(result)
    file.close()


if __name__ == "__main__":
    main()
