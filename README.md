# SecretSearcher
Python re-implementation of the classic SecretScanner shell script.

**NOTE:** For best results, ensure `colorama` is installed on the local system.

## Usage
Simply download `secret-searcher.py` to your path of choice and run it!

```
usage: secret-searcher.py [-h] [-e EXCLUDE] [-a ADD_EXCLUDE] [-i INCLUDE] [-d] [-f] [-p] [-c] [-w] [-s SECRETS]
                          [-l LIMIT] [-t THREADS] [-b BORDER] [-v {0,1,2,3}]
                          path

Searches the given path for exposed secrets.

positional arguments:
  path                  The path to search for secrets in.

options:
  -h, --help            show this help message and exit
  -e EXCLUDE, --exclude EXCLUDE
                        A comma-separated list of file or path exclusions.
  -a ADD_EXCLUDE, --add-exclude ADD_EXCLUDE
                        A comma-separated list of file or path exclusions to add to the default values.
  -i INCLUDE, --include INCLUDE
                        A comma-separated list of file or path inclusions.
  -d, --dotall          Whether or not to use DOTALL when matching.
  -f, --full-path       Whether or not to print the full path-names.
  -p, --show-span       Whether or not to print the span of the match.
  -c, --ignore-case     Whether or not to ignore the letter case during the search.
  -w, --disable-colors  Whether or not to disable colored output.
  -s SECRETS, --secrets SECRETS
                        A comma-separated list of target secrets (RegEx is supported).
  -l LIMIT, --limit LIMIT
                        The maximum size to consider searchable files.
  -t THREADS, --threads THREADS
                        The amount of threads to use for searching.
  -b BORDER, --border BORDER
                        The amount of characters to capture around each secret match.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        The level of verbosity to have.
```
