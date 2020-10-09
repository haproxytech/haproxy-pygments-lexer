from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    readme = fh.read()

setup (
  name="haproxy-pygments-lexer",
  version="1.0.0",
  license = "Apache Software License",
  author="HAProxy Technologies",
  author_email="nigniatovic@haproxy.com",
  url="https://github.com/haproxytech/haproxy-pygments-lexer",
  description="A Pygments Lexer for the HAProxy configuration syntax",
  long_description=readme,
  long_description_content_type="text/markdown",
  keywords = "haproxy syntax highlighting",
  platforms = "any",
  packages=find_packages(),
  python_requires=">=3",
  classifiers=[
    "Intended Audience :: Developers",
    "Intended Audience :: End Users/Desktop",
    "Intended Audience :: System Administrators"
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.5",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: OS Independent",
    "Topic :: Text Processing :: Filters",
    "Topic :: Utilities",
  ],
  entry_points =
  """
  [pygments.lexers]
  haproxylexer = haproxylexer.lexer:HAProxyLexer
  """,
)
