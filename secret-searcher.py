#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
from sys import exit
from time import time
from re import IGNORECASE, DOTALL, compile as RegEx, search
from queue import Empty
from multiprocessing import Queue, Event, Process, cpu_count
from time import sleep
from os.path import relpath as relative_path

try:
    from colorama import Fore, Back, Style, init as initialize_colorama
    initialize_colorama()
    __has_colorama = True
except ImportError:
    __has_colorama = False


# This is our recommended default exclusion list.
DEFAULT_EXCLUSIONS = ','.join((
    '*.jpg',
    '*.jpeg',
    '*.png',
    '*.gif',
    '*.css',
    '*.scss',
    '*.dex',
    '*.svg',
    '*.zip',
    '*.7z',
    '*.rar',
    '*.apk',
    '*.ipa',
    'node_modules/',
    '__pycache__/'
))

# This is our recommended default secret list.
DEFAULT_SECRETS = ','.join((
    r'[\.\'"`]eyJ',
    'API[\-_ ]*((Key)|(Token))',
    'secret',
    'sq0scp-',
    'AKIA',
    'ASIA',
    'MII',
    'SHA 1',
    'SHA 256',
    'Authorization',
    'BEGIN RSA',
    'BEGIN DSA',
    'BEGIN EC',
    'BEGIN PRIVATE',
    'BEGIN OPENSSH',
    'BEGIN SSH',
    'BEGIN PGP',
    'PuTTY-User-Key',
    'X-XSRF-TOKEN',
    'X-Amzn-Authorization',
))


def check_path(path, patterns):
    for pattern in patterns:
        if path.match(pattern):
            return True

    return False


def bytes_to_string(data):
    return str(data)[2:-1]


# We build an index of searchable files before starting.
def build_recursive_manifest(parent, context):
    total_files = 0

    for child in parent.iterdir():
        if not context['full_path']:
            child = Path(relative_path(child, '.'))

        if ((context['exclusions'] and check_path(child, context['exclusions'])) or
            (context['inclusions'] and not check_path(child, context['inclusions']))):
            if context['verbosity'] >= 2:
                context['message_queue'].put(f'Skipping a file (not included or specifically excluded): {child}')
            continue

        if context['verbosity'] >= 2:
            context['message_queue'].put(f'Skipping a file (not included or specifically excluded): {child}')

        if child.is_dir():
            if context['verbosity'] >= 3:
                context['message_queue'].put(f'Recursively searching directory: {child}')

            total_files += build_recursive_manifest(child, context)
        elif child.is_file():
            size = child.stat().st_size

            if size > context['size_limit']:
                if context['verbosity'] >= 1:
                    human_size_limit = bytes_to_unit_size(context['size_limit'])
                    human_size = bytes_to_unit_size(size)
                    context['message_queue'].put(f'Skipping a file (too big; {human_size} > {human_size_limit}): {child}')

                continue

            total_files += 1
            context['manifest_queue'].put(child)

    return total_files


def recursive_search(context):
    findings = 0

    while True:
        # We try to get the child, and if we can't, we break out.
        try:
            child = context['manifest_queue'].get_nowait()
        except Empty:
            break

        # We read our file into memory for faster searching.
        with open(child, 'rb') as file:
            contents = file.read()
            contents_size = file.tell()

        # We begin the search!
        for secret in context['secrets']:
            for match in secret.finditer(contents):
                findings += 1

                # We estimate the line index.
                line = contents[:match.span()[0]].count(b'\n') + 1

                match_start, match_end = match.span()

                if __has_colorama and not context['disable_colors']:
                    message = ''.join((
                        f'{Fore.MAGENTA}{child}{Style.RESET_ALL}',
                        ':',
                        f'{Fore.BLUE}L{line}{Style.RESET_ALL}',
                        ':',
                        f'{Fore.CYAN}{match.span()}{Style.RESET_ALL}' if context['show_span'] else '',
                        ':' if context['show_span'] else '',
                        bytes_to_string(contents[max(0, match_start - context['border']):match_start]),
                        f'{Back.RED}{Fore.WHITE}{Style.BRIGHT}{bytes_to_string(match.group())}{Style.RESET_ALL}',
                        bytes_to_string(contents[match_end:min(contents_size, match_end + context['border'])]),
                    ))
                else:
                    message = ''.join((
                        str(child),
                        ':',
                        f'L{line}',
                        ':',
                        str(match.span()) if context['show_span'] else '',
                        ':' if context['show_span'] else '',
                        bytes_to_string(contents[max(0, match_start - context['border']):match_start]),
                        bytes_to_string(match.group()),
                        bytes_to_string(contents[match_end:min(contents_size, match_end + context['border'])]),
                    ))

                context['message_queue'].put(message)

    context['findings_queue'].put((time(), findings))


def bytes_to_unit_size(count):
    units = ('B', 'KB', 'MB', 'GB', 'TB')
    index = 0

    while count >= 1024 and index < len(units):
        count /= 1024
        index += 1

    return f'{round(count, 2)} {units[index]}'


def unit_size_to_bytes(unit_size):
    table = {
        'TB': 1024 ** 4,
        'GB': 1024 ** 3,
        'MB': 1024 ** 2,
        'KB': 1024,
        'B': 1
    }

    match = search(r'^([\s\d\.]+)(.*)$', unit_size)

    if not match:
        raise ValueError('The supplied unit size is invalid!')

    unit = match.group(2).strip().upper()

    if unit and unit not in table:
        raise ValueError('The supplied unit is not supported!')

    return float(match.group(1)) * table[unit or 'B']


# Although I hate it, if this wasn't done, different print statements
# would write to STDOUT at the same time and break everything really,
# really badly.
def print_messages(context):
    while True:
        try:
            print(context['message_queue'].get(timeout=1))
        except Empty:
            if context['search_completed'].is_set():
                break


def main():
    parser = ArgumentParser(description='Searches the given path for exposed secrets.')
    parser.add_argument('path', help='The path to search for secrets in.')
    parser.add_argument('-e', '--exclude', default=DEFAULT_EXCLUSIONS, help='A comma-separated list of file or path exclusions.')
    parser.add_argument('-a', '--add-exclude', help='A comma-separated list of file or path exclusions to add to the default values.')
    parser.add_argument('-i', '--include', help='A comma-separated list of file or path inclusions.')
    parser.add_argument('-d', '--dotall', action='store_true', help='Whether or not to use DOTALL when matching.')
    parser.add_argument('-f', '--full-path', action='store_true', help='Whether or not to print the full path-names.')
    parser.add_argument('-p', '--show-span', action='store_true', help='Whether or not to print the span of the match.')
    parser.add_argument('-c', '--ignore-case', action='store_true', help='Whether or not to ignore the letter case during the search.')
    parser.add_argument('-w', '--disable-colors', action='store_true', help='Whether or not to disable colored output.')
    parser.add_argument('-s', '--secrets', default=DEFAULT_SECRETS, help='A comma-separated list of target secrets (RegEx is supported).')
    parser.add_argument('-l', '--limit', default='32MB', help='The maximum size to consider searchable files.')
    parser.add_argument('-t', '--threads', help='The amount of threads to use for searching.')
    parser.add_argument('-b', '--border', default='40', help='The amount of characters to capture around each secret match.')
    parser.add_argument('-v', '--verbosity', default=1, choices=['0', '1', '2', '3'], help='The level of verbosity to have.')
    arguments = parser.parse_args()

    # We start out by making sure that the target path exists.
    target_path = Path(arguments.path).resolve()

    if not target_path.exists():
        print('The target path does not exist:', target_path)
        exit()

    # We make sure these values are not unspecified and that they have a value.
    exclusions = ()

    if arguments.exclude is not None and arguments.exclude.strip():
        exclusions = arguments.exclude.split(',')

    if arguments.add_exclude is not None and arguments.add_exclude.strip():
        exclusions += arguments.add_exclude.split(',')

    inclusions = ()

    if arguments.include is not None and arguments.include.strip():
        inclusions = arguments.include.split(',')

    # We setup our flags and compile our secrets into RegEx to make things
    # a little more performant.
    flags = 0

    if arguments.dotall:
        flags |= DOTALL

    if arguments.ignore_case:
        flags |= IGNORECASE

    secrets = ()

    if arguments.secrets is not None and arguments.secrets.strip():
        secrets = [RegEx(secret.encode(), flags=flags) for secret in arguments.secrets.split(',')]

    # We setup our context object.
    context = {
        'secrets': secrets,
        'exclusions': exclusions,
        'inclusions': inclusions,
        'size_limit': unit_size_to_bytes(arguments.limit),
        'border': int(arguments.border),
        'verbosity': int(arguments.verbosity),
        'full_path': arguments.full_path,
        'show_span': arguments.show_span,
        'disable_colors': arguments.disable_colors,
        'manifest_queue': Queue(),
        'findings_queue': Queue(),
        'message_queue': Queue(),
        'search_completed': Event()
    }

    # Our pre-setup is done, time to begin the search!
    started_at = time()

    # We create a manifest for our search.
    total_files = build_recursive_manifest(target_path, context)

    # We setup our worker threads (they're processes, but just pretend they're
    # threads so I don't have to re-write this bit).
    if arguments.threads is not None:
        threads = int(arguments.threads)
    else:
        threads = cpu_count()

    workers = []

    for worker_id in range(threads):
        workers.append(Process(target=recursive_search, args=(context,)))

    message_worker = Process(target=print_messages, args=(context,))

    # Once our workers are setup, we start them.
    message_worker.start()

    for worker in workers:
        worker.start()

    # We wait for the queue to fill-up.
    while True:
        if context['findings_queue'].qsize() == threads:
            break

        sleep(1)

    # We end our message worker.
    context['search_completed'].set()
    message_worker.join()

    # We calculate our findings.
    total_findings = 0
    latest_timestamp = None

    while True:
        try:
            timestamp, findings = context['findings_queue'].get_nowait()
            total_findings += findings

            if latest_timestamp is None or timestamp > latest_timestamp:
                latest_timestamp = timestamp
        except Empty:
            break

    time_taken = latest_timestamp - started_at

    # Time to make it pretty for the end-user.
    if __has_colorama and not context['disable_colors']:
        total_findings = f'{Style.BRIGHT}{Fore.GREEN if total_findings else Fore.RED}{total_findings}{Style.RESET_ALL}'

    print('Search was completed over', total_files, 'files with', total_findings, 'matches found.', f'(Searching took {time_taken:.2f} seconds)')


if __name__ == '__main__':
    main()
