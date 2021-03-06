from fsa_translator import *


INPUT_FILE = "fsa.txt"
OUTPUT_FILE = "result.txt"


def make_list(line):
    """
    Transform the input line into a set of strings
    :param line:  an input line
    :return: a set of strings
    """
    line = line.strip().split("=")[1][1:-1].split(",")
    if line == [""]:
        return []
    new_list = []
    for item in line:
        if len(line) > 0 and ">" in item:
            obj = tuple(item.split(">"))
        else:
            obj = item
        if obj not in new_list:
            new_list.append(obj)
    return new_list


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
        states, alpha, init_state, fin_states, trans = (make_list(line) for line in lines)
        result = translate_fsa(states, alpha, init_state, fin_states, trans)
        file.close()
    except SyntaxError:
        result = get_malformed_error()
    except Exception as e:
        result = get_malformed_error()
    file = open(OUTPUT_FILE, "w")
    file.write(result)
    file.close()


if __name__ == "__main__":
    main()
