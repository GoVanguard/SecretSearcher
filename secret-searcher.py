#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
from sys import exit
from time import time
from re import IGNORECASE, DOTALL, search, escape, finditer

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


# We use recursive search instead of glob since it keeps unwanted children out of our search.
def recursive_search(parent, configuration):
	searched = 0
	findings = 0

	for child in parent.iterdir():
		if (configuration['exclusions'] and check_path(child, configuration['exclusions'])) \
		or (configuration['inclusions'] and not check_path(child, configuration['inclusions'])):
			if configuration['verbosity'] >= 2:
				print(f'Skipping a file (not included or specifically excluded):', child)

			continue

		if child.is_dir():
			if configuration['verbosity'] >= 3:
				print('Recursively searching directory:', child)

			sub_findings, sub_searched = recursive_search(child, configuration)
			findings += sub_findings
			searched += sub_searched
		elif child.is_file():
			if configuration['verbosity'] >= 3:
				print('Searching file contents:', child)

			size = child.stat().st_size

			if size > configuration['size_limit']:
				if configuration['verbosity'] >= 1:
					human_size_limit = bytes_to_unit_size(configuration['size_limit'])
					human_size = bytes_to_unit_size(size)
					print(f'Skipping a file (too big; {human_size} > {human_size_limit}):', child)

				continue

			# We read our file into memory for faster searching.
			with open(child, 'rb') as file:
				contents = file.read()
				contents_size = file.tell()

			# We begin the search!
			for secret in configuration['secrets']:
				regex = f'({secret})'

				# We setup our flags for the capture.
				flags = DOTALL

				if configuration['ignore_case']:
					flags |= IGNORECASE

				for match in finditer(regex.encode(), contents, flags=flags):
					findings += 1

					# We estimate the line index.
					line = contents[:match.span()[0]].count(b'\n') + 1

					match_start, match_end = match.span()

					if __has_colorama:
						message = ''.join((
							f'{Back.MAGENTA}{Fore.WHITE}{Style.BRIGHT}{child}{Style.RESET_ALL}',
							':',
							f'{Back.BLUE}{Fore.WHITE}{Style.BRIGHT}L{line}{Style.RESET_ALL}',
							':',
							f'{Back.CYAN}{Fore.WHITE}{Style.BRIGHT}{match.span()}{Style.RESET_ALL}' if configuration['show_span'] else '',
							':' if configuration['show_span'] else '',
							bytes_to_string(contents[max(0, match_start - configuration['border']):match_start]),
							f'{Back.RED}{Fore.WHITE}{Style.BRIGHT}{bytes_to_string(match.group())}{Style.RESET_ALL}',
							bytes_to_string(contents[match_end:min(contents_size, match_end + configuration['border'])]),
						))
					else:
						message = ''.join((
							str(child),
							':',
							f'L{line}',
							':',
							str(match.span()) if configuration['show_span'] else '',
							':' if configuration['show_span'] else '',
							bytes_to_string(contents[max(0, match_start - configuration['border']):match_start]),
							bytes_to_string(match.group()),
							bytes_to_string(contents[match_end:min(contents_size, match_end + configuration['border'])]),
						))

					print(message)

			searched += 1

	return findings, searched


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


def main():
	parser = ArgumentParser(description='Searches the given path for exposed secrets.')
	parser.add_argument('path', help='The path to search for secrets in.')
	parser.add_argument('-e', '--exclude', default=DEFAULT_EXCLUSIONS, help='A comma-separated list of file or path exclusions.')
	parser.add_argument('-a', '--add-exclude', help='A comma-separated list of file or path exclusions to add to the default values.')
	parser.add_argument('-i', '--include', help='A comma-separated list of file or path inclusions.')
	parser.add_argument('-p', '--show-span', action='store_true', help='Whether or not to print the span of the match.')
	parser.add_argument('-c', '--ignore-case', action='store_true', help='Whether or not to ignore the letter case during the search.')
	parser.add_argument('-s', '--secrets', default=DEFAULT_SECRETS, help='A comma-separated list of target secrets (RegEx is supported).')
	parser.add_argument('-l', '--limit', default='32MB', help='The maximum size to consider searchable files.')
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

	secrets = ()

	if arguments.secrets is not None and arguments.secrets.strip():
		secrets = arguments.secrets.split(',')

	# We setup our configuration object.
	configuration = {
		'secrets': secrets,
		'exclusions': exclusions,
		'inclusions': inclusions,
		'size_limit': unit_size_to_bytes(arguments.limit),
		'border': int(arguments.border),
		'verbosity': int(arguments.verbosity),
		'ignore_case': arguments.ignore_case,
		'show_span': arguments.show_span
	}

	# Our pre-setup is done, time to begin the search!
	started_at = time()

	findings, searched = recursive_search(target_path, configuration)

	if __has_colorama:
		findings = f'{Style.BRIGHT}{Fore.GREEN if findings else Fore.RED}{findings}{Style.RESET_ALL}'

	print('Search was completed over', searched, 'files with', findings, 'matches found.', f'(Took {time() - started_at:.2f} seconds)')


if __name__ == '__main__':
	main()
