install:
	python setup.py install

test:
	pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x -f html -O full -o haproxy.html haproxy.cfg
	pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x -f html -O full -O style=autumn -o haproxy2.html haproxy.cfg
	pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x -f html -O full -O style=vim -o haproxy3.html haproxy.cfg
	pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x -f html -O full -O style=emacs -o haproxy4.html haproxy.cfg
	pygmentize -l ./haproxylexer/lexer.py:HAProxyLexer -x -f html -O full -O style=monokai -o haproxy5.html haproxy.cfg
