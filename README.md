# Pygments Lexer for the HAProxy configuration syntax

This package enables the latest HAProxy configuration syntax highlighting for
python [Pygments](https://github.com/pygments/pygments) and is used as the
basis for the HAProxy lexer on the Pygments project.

The lexer keywords are maintained and updated manually using information from
the documentation of the HAProxy Community version and the HAProxy Enterprise
version.

## Installation

To add the lexer on your already existing pygments installation run:

```
python setup.py install
```

This will install the lexer on your local system and create a python package.

To verify that the lexer is working use the sample HAProxy configuration file.

```
# Output the result on your command line
pygmentize -l haproxy -x haproxy.cfg

# Output the result in an HTML file
pygmentize -O full -l haproxy -o haproxy.html haproxy.cfg
```

## Development

The main grammar rules and keywords are located under `haproxylexer`.

- `_haproxy_builtins.py` contains lists of keywords.
- `lexer.py` contains all the grammar regexes

To quickly test your changes you can run:

```
pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x haproxy.cfg
```

## Contributing

Pull requests and patches will be checked out by the maintainer and merged.
Try to keep your commit messages precise and to the point.

## Thanks and resources

Many thanks for the lovely [Python](https://www.python.org/doc/), [PyPi](https://pypi.org/), and [Pygments](https://pygments.org/docs/) documentation.

Also a shout out to [Bojan Marcovic](https://github.com/bmarkovic) for his [vscode-haproxy-syntax](https://github.com/bmarkovic/vscode-haproxy-syntax) and [Alexander Bulimov](https://github.com/abulimov) for his [atom-language-haproxy](https://github.com/abulimov/atom-language-haproxy). Both were a great starting resources and the work done here will be also now easier to port for editors like VS Code, Atom, Sublime, etc.

## Funny little disclaimer

The author, has never actually taken the time to learn python...

He just hacked away at this. Please forgive him for any coding "faux passes" he might have done :)
