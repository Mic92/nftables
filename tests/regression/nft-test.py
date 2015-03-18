#!/usr/bin/python
#
# (C) 2014 by Ana Rey Botello <anarey@gmail.com>
#
# Based on iptables-test.py:
# (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>"
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Thanks to the Outreach Program for Women (OPW) for sponsoring this test
# infrastructure.

import sys
import os
import subprocess
import argparse
import signal

TERMINAL_PATH = os.getcwd()
TESTS_PATH = os.path.dirname(os.path.abspath(__file__))
TESTS_DIRECTORY = ["any", "arp", "bridge", "inet", "ip", "ip6"]
LOGFILE = "/tmp/nftables-test.log"
log_file = None
table_list = []
chain_list = []
all_set = dict()
signal_received = 0


class Colors:
    HEADER = '\033[95m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'


def print_error(reason, filename=None, lineno=None):
    '''
    Prints an error with nice colors, indicating file and line number.
    '''
    if filename and lineno:
        print (filename + ": " + Colors.RED + "ERROR:" +
               Colors.ENDC + " line %d: %s" % (lineno + 1, reason))
    else:
        print (Colors.RED + "ERROR:" + Colors.ENDC + " %s" % (reason))


def print_warning(reason, filename=None, lineno=None):
    '''
    Prints a warning with nice colors, indicating file and line number.
    '''
    if filename and lineno:
        print (filename + ": " + Colors.YELLOW + "WARNING:" + \
               Colors.ENDC + " line %d: %s" % (lineno + 1, reason))
    else:
        print (Colors.YELLOW + "WARNING:" + " %s" % (reason))


def print_differences_warning(filename, lineno, rule1, rule2, cmd):
    reason = "'" + rule1 + "' mismatches '" + rule2 + "'"
    print filename + ": " + Colors.YELLOW + "WARNING: " + Colors.ENDC + \
        "line: " + str(lineno + 1) + ": '" + cmd + "': " + reason


def print_differences_error(filename, lineno, output, cmd):
    reason = "Listing is broken."
    print filename + ": " + Colors.RED + "ERROR: " + Colors.ENDC + \
        "line: " + str(lineno + 1) + ": '" + cmd + "': " + reason


def table_exist(table, filename, lineno):
    '''
    Exists a table.
    '''
    cmd = "nft list -nnn table " + table[0] + " " + table[1]
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def table_flush(table, filename, lineno):
    '''
    Flush a table.
    '''
    cmd = "nft flush table " + str(table[0]) + " " + str(table[1])
    ret = execute_cmd(cmd, filename, lineno)

    return cmd


def table_create(table, filename, lineno):
    '''
    Adds a table.
    '''
    ## We check if table exists.
    if table_exist(table, filename, lineno):
        reason = "Table " + table[1] + " already exists"
        print_error(reason, filename, lineno)
        return -1

    table_list.append(table)

    ## We add a new table
    cmd = "nft add table " + table[0] + " " + table[1]
    ret = execute_cmd(cmd, filename, lineno)

    if ret != 0:
        reason = "Cannot add table " + table[1]
        print_error(reason, filename, lineno)
        table_list.remove(table)
        return -1

    ## We check if table was added correctly.
    if not table_exist(table, filename, lineno):
        table_list.remove(table)
        reason = "I have just added the table " + table[1] + \
            " but it does not exist. Giving up!"
        print_error(reason, filename, lineno)
        return -1

    return 0


def table_delete(table, filename=None, lineno=None):
    '''
    Deletes a table.
    '''
    table_info = " " + table[0] + " " + table[1] + " "

    if not table_exist(table, filename, lineno):
        reason = "Table " + table[1] + \
            " does not exist but I added it before."
        print_error(reason, filename, lineno)
        return -1

    cmd = "nft delete table" + table_info
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = cmd + ": " \
            "I cannot delete table '" + table[1] + "'. Giving up! "
        print_error(reason, filename, lineno)
        return -1

    if table_exist(table, filename, lineno):
        reason = "I have just deleted the table " + table[1] + \
            " but the table still exists."
        print_error(reason, filename, lineno)
        return -1

    return 0


def chain_exist(chain, table, filename, lineno):
    '''
    Checks a chain
    '''

    table_info = " " + table[0] + " " + table[1] + " "
    cmd = "nft list -nnn chain" + table_info + chain
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def chain_create(chain, chain_type, chain_list, table, filename, lineno):
    '''
    Adds a chain
    '''

    table_info = " " + table[0] + " " + table[1] + " "

    if chain_exist(chain, table, filename, lineno):
        reason = "This chain '" + chain + "' exists in " + table[1] + "." + \
            "I cannot create two chains with same name."
        print_error(reason, filename, lineno)
        return -1

    if chain_type:
        cmd = "nft add chain" + table_info + chain + "\{ " + chain_type + "\; \}"
    else:
        cmd = "nft add chain" + table_info + chain

    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = "I cannot create the chain '" + chain
        print_error(reason, filename, lineno)
        return -1

    if not chain in chain_list:
        chain_list.append(chain)

    if not chain_exist(chain, table, filename, lineno):
        reason = "I have added the chain '" + chain + \
            "' but it does not exist in " + table[1]
        print_error(reason, filename, lineno)
        return -1

    return 0


def chain_delete(chain, table,  filename=None, lineno=None):
    '''
    Flushes and deletes a chain.
    '''

    table_info = " " + table[0] + " " + table[1] + " "

    if not chain_exist(chain, table, filename, lineno):
        reason = "The chain " + chain + " does not exists in " + table[1] + \
            ". I cannot delete it."
        print_error(reason, filename, lineno)
        return -1

    cmd = "nft flush chain" + table_info + chain
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = "I cannot flush this chain " + chain
        print_error(reason, filename, lineno)
        return -1

    cmd = "nft delete chain" + table_info + chain
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = cmd + "I cannot delete this chain. DD"
        print_error(reason, filename, lineno)
        return -1

    if chain_exist(chain, table, filename, lineno):
        reason = "The chain " + chain + " exists in " + table[1] + \
            ". I cannot delete this chain"
        print_error(reason, filename, lineno)
        return -1

    return 0


def set_add(set_info, table_list, filename, lineno):
    '''
    Adds a set.
    '''

    if not table_list:
        reason = "Missing table to add rule"
        print_error(reason, filename, lineno)
        return -1

    for table in table_list:
        if set_exist(set_info[0], table, filename, lineno):
            reason = "This set " + set_info + " exists in " + table[1] + \
                ". I cannot add it again"
            print_error(reason, filename, lineno)
            return -1

        table_info = " " + table[0] + " " + table[1] + " "
        set_text = " " + set_info[0] + " { type " + set_info[1] + " \;}"
        cmd = "nft add set" + table_info + set_text
        ret = execute_cmd(cmd, filename, lineno)

        if (ret == 0 and set_info[2].rstrip() == "fail") or \
           (ret != 0 and set_info[2].rstrip() == "ok"):
                reason = cmd + ": " + "I cannot add the set " + set_info[0]
                print_error(reason, filename, lineno)
                return -1

        if not set_exist(set_info[0], table, filename, lineno):
            reason = "I have just added the set " + set_info[0] + \
                " to the table " + table[1] + " but it does not exist"
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_add_elements(set_element, set_name, set_all, state, table_list,
                     filename, lineno):
    '''
    Adds elements to the set.
    '''

    if not table_list:
        reason = "Missing table to add rules"
        print_error(reason, filename, lineno)
        return -1

    for table in table_list:
        # Check if set exists.
        if (not set_exist(set_name, table, filename, lineno) or
           not set_name in set_all) and state == "ok":
            reason = "I cannot add an element to the set " + set_name + \
                " since it does not exist."
            print_error(reason, filename, lineno)
            return -1

        table_info = " " + table[0] + " " + table[1] + " "

        element = ""
        for e in set_element:
            if not element:
                element = e
            else:
                element = element + ", " + e

        set_text = set_name + " { " + element + " }"
        cmd = "nft add element" + table_info + set_text
        ret = execute_cmd(cmd, filename, lineno)

        if (state == "fail" and ret == 0) or (state == "ok" and ret != 0):
                test_state = "This rule should have failed."
                reason = cmd + ": " + test_state
                print_error(reason, filename, lineno)
                return -1

        # Add element into a all_set.
        if (ret == 0 and state == "ok"):
            for e in set_element:
                set_all[set_name].add(e)

    return 0


def set_delete_elements(set_element, set_name, table, filename=None,
                        lineno=None):
    '''
    Deletes elements in a set.
    '''
    table_info = " " + table[0] + " " + table[1] + " "

    for element in set_element:
        set_text = set_name + " {" + element + "}"
        cmd = "nft delete element" + table_info + set_text
        ret = execute_cmd(cmd, filename, lineno)
        if ret != 0:
            reason = "I cannot delete an element" + element + \
                " from the set '" + set_name
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_delete(all_set, table, filename=None, lineno=None):
    '''
    Deletes set and its content.
    '''

    for set_name in all_set.keys():
        # Check if exists the set
        if not set_exist(set_name, table, filename, lineno):
            reason = "The set " + set_name + \
                " does not exist, I cannot delete it"
            print_error(reason, filename, lineno)
            return -1

        # We delete all elements in the set
        set_delete_elements(all_set[set_name], set_name, table, filename,
                            lineno)

        # We delete the set.
        table_info = " " + table[0] + " " + table[1] + " "
        cmd = "nft delete set " + table_info + " " + set_name
        ret = execute_cmd(cmd, filename, lineno)

        # Check if the set still exists after I deleted it.
        if ret != 0 or set_exist(set_name, table, filename, lineno):
            reason = "Cannot remove the set " + set_name
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_exist(set_name, table, filename, lineno):
    '''
    Check if the set exists.
    '''
    table_info = " " + table[0] + " " + table[1] + " "
    cmd = "nft list -nnn set" + table_info + set_name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def set_check_element(rule1, rule2):
    '''
    Check if element exists in anonymous sets.
    '''
    ret = -1
    pos1 = rule1.find("{")
    pos2 = rule2.find("{")
    end1 = rule1.find("}")
    end2 = rule2.find("}")

    if ((pos1 != -1) and (pos2 != -1) and (end1 != -1) and (end2 != -1)):
        list1 = (rule1[pos1 + 1:end1].replace(" ", "")).split(",")
        list2 = (rule2[pos2 + 1:end2].replace(" ", "")).split(",")
        list1.sort()
        list2.sort()
        if (cmp(list1, list2) == 0):
            ret = 0
    return ret


def output_clean(pre_output, chain):
    pos_chain = pre_output[0].find(chain)
    if pos_chain == -1:
        return ""
    output_intermediate = pre_output[0][pos_chain:]
    brace_start = output_intermediate.find("{")
    brace_end = output_intermediate.find("}")
    pre_rule = output_intermediate[brace_start:brace_end]
    if pre_rule[1:].find("{") > -1:  # this rule has a set.
        set = pre_rule[1:].replace("\t", "").replace("\n", "").strip()
        set = set.split(";")[2].strip() + "}"
        return set
    else:
        rule = pre_rule.split(";")[2].replace("\t", "").replace("\n", "").strip()
    if len(rule) < 0:
        return ""
    return rule


def rule_add(rule, table_list, chain_list, filename, lineno,
             force_all_family_option):
    '''
    Adds a rule
    '''
    # TODO Check if a rule is added correctly.
    ret = warning = error = unit_tests = 0

    if not table_list or not chain_list:
        reason = "Missing table or chain to add rule."
        print_error(reason, filename, lineno)
        return [-1, warning, error, unit_tests]

    for table in table_list:
        for chain in chain_list:
            if len(rule) == 1:
                reason = "Skipping malformed test. (" + \
                    str(rule[0].rstrip('\n')) + ")"
                print_warning(reason, filename, lineno)
                continue

            unit_tests += 1
            table_flush(table, filename, lineno)
            table_info = " " + table[0] + " " + table[1] + " "
            cmd = "nft add rule" + table_info + chain + " " + rule[0]

            ret = execute_cmd(cmd, filename, lineno)

            state = rule[1].rstrip()
            if (ret == 0 and state == "fail") or (ret != 0 and state == "ok"):
                if state == "fail":
                    test_state = "This rule should have failed."
                else:
                    test_state = "This rule should not have failed."
                reason = cmd + ": " + test_state
                print_error(reason, filename, lineno)
                ret = -1
                error += 1
                if not force_all_family_option:
                    return [ret, warning, error, unit_tests]

            if (state == "fail" and ret != 0):
                ret = 0
                continue

            if ret == 0:
            # Check output of nft
                process = subprocess.Popen(['nft', '-nnn', 'list', 'table'] + table,
                                           shell=False, stdout=subprocess.PIPE,
                                           preexec_fn=preexec)
                pre_output = process.communicate()
                output = pre_output[0].split(";")
                if len(output) < 2:
                    reason = cmd + ": Listing is broken."
                    print_error(reason, filename, lineno)
                    ret = -1
                    error += 1
                    if not force_all_family_option:
                        return [ret, warning, error, unit_tests]
                else:
                    rule_output = output_clean(pre_output, chain)
                    if (len(rule) == 3):
                        teoric_exit = rule[2]
                    else:
                        teoric_exit = rule[0]

                    if (rule_output.rstrip() != teoric_exit.rstrip()):
                        if (rule[0].find("{") != -1):  # anonymous sets
                            if (set_check_element(teoric_exit, rule_output) != 0):
                                warning += 1
                                print_differences_warning(filename, lineno,
                                                          rule[0], rule_output,
                                                          cmd)
                                if not force_all_family_option:
                                    return [ret, warning, error, unit_tests]
                        else:
                            if len(rule_output) <= 0:
                                error += 1
                                print_differences_error(filename, lineno,
                                                        rule_output, cmd)
                                if not force_all_family_option:
                                    return [ret, warning, error, unit_tests]

                            warning += 1
                            print_differences_warning(filename, lineno,
                                                      rule[0], rule_output,
                                                      cmd)

                            if not force_all_family_option:
                                return [ret, warning, error, unit_tests]

    return [ret, warning, error, unit_tests]


def preexec():
    os.setpgrp()  # Don't forward signals.


def cleanup_on_exit():
    for table in table_list:
        for chain in chain_list:
            ret = chain_delete(chain, table, "", "")
        if all_set:
            ret = set_delete(all_set, table)
        ret = table_delete(table)


def signal_handler(signal, frame):
    global signal_received
    signal_received = 1


def execute_cmd(cmd, filename, lineno):
    '''
    Executes a command, checks for segfaults and returns the command exit
    code.

    :param cmd: string with the command to be executed
    :param filename: name of the file tested (used for print_error purposes)
    :param lineno: line number being tested (used for print_error purposes)
    '''
    global log_file
    print >> log_file, "command: %s" % cmd
    if debug_option:
        print cmd
    ret = subprocess.call(cmd, shell=True, universal_newlines=True,
                          stderr=subprocess.STDOUT, stdout=log_file,
                          preexec_fn=preexec)
    log_file.flush()

    if ret == -11:
        reason = "command segfaults: " + cmd
        print_error(reason, filename, lineno)

    return ret


def print_result(filename, tests, warning, error):
    return str(filename) + ": " + str(tests) + " unit tests, " + \
        str(error) + " error, " + str(warning) + " warning"


def print_result_all(filename, tests, warning, error, unit_tests):
        return str(filename) + ": " + str(tests) + " unit tests, " +\
            str(unit_tests) + " total test executed, " + \
            str(error) + " error, " + \
            str(warning) + " warning"


def table_process(table_line, filename, lineno):
    if ";" in table_line:
        table_info = table_line.split(";")
    else:
        table_info.append("ip")
        table_info.append(table_line)

    return table_create(table_info, filename, lineno)


def chain_process(chain_line, filename, lineno):
    chain_name = chain_line[0]
    chain_type = ""
    for table in table_list:
        if len(chain_line) > 1:
            chain_type = chain_line[1]
        ret = chain_create(chain_name, chain_type, chain_list, table,
                            filename, lineno)
        if ret != 0:
            return -1
    return ret


def set_process(set_line, filename, lineno):
    set_info = []
    set_name = "".join(set_line[0].rstrip()[1:])
    set_info.append(set_name)
    set_type = set_line[1].split(";")[0]
    set_state = set_line[1].split(";")[1]  # ok or fail
    set_info.append(set_type)
    set_info.append(set_state)
    ret = set_add(set_info, table_list, filename, lineno)
    if ret == 0:
        all_set[set_name] = set()

    return ret


def set_element_process(element_line, filename, lineno):
    rule_state = element_line[1]
    set_name = element_line[0].split(" ")[0]
    set_element = element_line[0].split(" ")
    set_element.remove(set_name)
    return set_add_elements(set_element, set_name, all_set, rule_state,
                            table_list, filename, lineno)


def run_test_file(filename, force_all_family_option, specific_file):
    '''
    Runs a test file

    :param filename: name of the file with the test rules
    '''

    if specific_file:
        filename_path = os.path.join(TERMINAL_PATH, filename)
    else:
        filename_path = os.path.join(TESTS_PATH, filename)

    f = open(filename_path)
    tests = passed = total_unit_run = total_warning = total_error = 0
    table = ""
    total_test_passed = True

    for lineno, line in enumerate(f):
        if signal_received == 1:
            print "\nSignal received. Cleaning up and Exitting..."
            cleanup_on_exit()
            sys.exit(0)

        if line.isspace():
            continue

        if line[0] == "#":  # Command-line
            continue

        if line[0] == '*':  # Table
            table_line = line.rstrip()[1:]
            ret = table_process(table_line, filename, lineno)
            if (ret != 0):
                total_test_passed = False
                break
            continue

        if line[0] == ":":  # Chain
            chain_line = line.rstrip()[1:].split(";")
            ret = chain_process(chain_line, filename, lineno)
            if ret != 0:
                total_test_passed = False
                break
            continue

        if line[0] == "!":  # Adds this set
            set_line = line.rstrip()[0:].split(" ")
            ret = set_process(set_line, filename, lineno)
            tests += 1
            if ret == -1:
                total_test_passed = False
                continue
            passed += 1
            continue

        if line[0] == "?":  # Adds elements in a set
            element_line = line.rstrip()[1:].split(";")
            ret = set_element_process(element_line, filename, lineno)
            tests += 1
            if ret == -1:
                total_test_passed = False
                continue

            passed += 1
            continue

        # Rule
        rule = line.split(';')  # rule[1] Ok or FAIL
        if line[0] == "-":  # Run omitted lines
            if line[1:].find("*") != -1:
                continue
            if need_fix_option:
                rule[0] = rule[0].rstrip()[1:].strip()
            else:
                continue
        elif need_fix_option:
            continue

        result = rule_add(rule, table_list, chain_list, filename, lineno,
                          force_all_family_option)
        tests += 1
        ret = result[0]
        warning = result[1]
        total_warning += warning
        total_error += result[2]
        total_unit_run += result[3]

        if ret != 0:
            total_test_passed = False
            continue

        if warning == 0:  # All ok.
            passed += 1

    # Delete rules, sets, chains and tables
    for table in table_list:
        # We delete chains
        for chain in chain_list:
            ret = chain_delete(chain, table, filename, lineno)
            if ret != 0:
                total_test_passed = False

        # We delete sets.
        if all_set:
            ret = set_delete(all_set, table, filename, lineno)
            if ret != 0:
                total_test_passed = False
                reason = "There is a problem when we delete a set"
                print_error(reason, filename, lineno)

        # We delete tables.
        ret = table_delete(table, filename, lineno)

        if ret != 0:
            total_test_passed = False

    if specific_file:
        if force_all_family_option:
            print print_result_all(filename, tests, total_warning, total_error,
                                   total_unit_run)
        else:
            print print_result(filename, tests, total_warning, total_error)
    else:
        if (tests == passed and tests > 0):
            print filename + ": " + Colors.GREEN + "OK" + Colors.ENDC

    f.close()
    del table_list[:]
    del chain_list[:]
    all_set.clear()

    return [tests, passed, total_warning, total_error, total_unit_run]


def main():
    parser = argparse.ArgumentParser(description='Run nft tests',
                                     version='1.0')

    parser.add_argument('filename', nargs='?',
                        metavar='path/to/file.t',
                        help='Run only this test')

    parser.add_argument('-d', '--debug', action='store_true',
                        dest='debug',
                        help='enable debugging mode')

    parser.add_argument('-e', '--need-fix', action='store_true',
                        dest='need_fix_line',
                        help='run rules that need a fix')

    parser.add_argument('-f', '--force-family', action='store_true',
                        dest='force_all_family',
                        help='keep testing all families on error')

    args = parser.parse_args()
    global debug_option, need_fix_option
    debug_option = args.debug
    need_fix_option = args.need_fix_line
    force_all_family_option = args.force_all_family
    specific_file = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if os.getuid() != 0:
        print "You need to be root to run this, sorry"
        return

    test_files = files_ok = run_total = 0
    tests = passed = warnings = errors = 0
    global log_file
    try:
        log_file = open(LOGFILE, 'w')
    except IOError:
        print "Cannot open log file %s" % LOGFILE
        return

    file_list = []
    if args.filename:
        file_list = [args.filename]
        specific_file = True
    else:
        for directory in TESTS_DIRECTORY:
            path = os.path.join(TESTS_PATH, directory)
            for root, dirs, files in os.walk(path):
                for f in files:
                    if f.endswith(".t"):
                        file_list.append(os.path.join(directory, f))

    for filename in file_list:
        result = run_test_file(filename, force_all_family_option, specific_file)
        file_tests = result[0]
        file_passed = result[1]
        file_warnings = result[2]
        file_errors = result[3]
        file_unit_run = result[4]

        test_files += 1

        if file_warnings == 0 and file_tests == file_passed:
            files_ok += 1
        if file_tests:
            tests += file_tests
            passed += file_passed
            errors += file_errors
            warnings += file_warnings
        if force_all_family_option:
            run_total += file_unit_run

    if test_files == 0:
        print "No test files to run"
    else:
        if not specific_file:
            if force_all_family_option:
                print ("%d test files, %d files passed, %d unit tests, %d total executed, %d error, %d warning" %
                      (test_files, files_ok, tests, run_total, errors, warnings))
            else:
                print ("%d test files, %d files passed, %d unit tests, %d error, %d warning" %
                      (test_files, files_ok, tests, errors, warnings))

if __name__ == '__main__':
    main()
