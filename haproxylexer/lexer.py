from pygments.lexer import RegexLexer, bygroups, using, words
from pygments.token import *
# from pygments.lexers.web import JavascriptLexer

from haproxylexer import _haproxy_builtins

class HAProxyLexer(RegexLexer):
    name = 'HAProxyCFG'
    aliases = ['haproxy', 'hapee-lb']
    filenames = ['haproxy*.cfg', 'hapee-lb*.cfg']

    tokens = {
        'root': [
            # HAProxy configuration parsing basics.
            # - A typical file is split into sections.
            # - To declare a section you need to use its keyword at the start of
            #   the line.
            # - Only sections and comments are allowed at the start of the line.
            # - Configuration keywords always start with indentation either by
            #   space or tabs or a mix of the two.

            # Based on the latest HAProxy Enterprise Configuration manual
            # https://www.haproxy.com/documentation/hapee/latest/onepage/

            # Comment that starts at the beginning of the line
            # Regex:
            # Start at the start of the line
            # Look for a #
            # Grab everything till the end of line
            (r'^#.*$', Comment.Singleline),

            # Inline comment
            # Regex:
            # Look for whitespace followed by #
            # Grab everything till the end of line
            (r'(?<=\s)#.*$', Comment.Singleline),

            # Path
            (r'(\s)(\/\S+)', bygroups(Text, String)),
            # Path at the end of the line
            (r'(\s)(\/\S+)$', bygroups(Text, String)),

            # Urls
            (r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', String),

            # Quoted strings
            (r'(\".*?\")', bygroups(String.Double)),
            (r'(\'.*?\')', bygroups(String.Single)),

            # dashed options
            (r'(?<=\s)(-)(m|i)(?=\s)', bygroups(Text, Name.Attribute)),

            # Main Sections
            # RegEx:
            # Start at the start of the line
            # Look for any of the keywords (Group 1)
            # Look for whitespace - matches 0 or more (Group 2)
            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Keyword.Namespace, Text, Name.Variable, Text, Number, Number, Text)),
            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Keyword.Namespace, Text, Name.Variable, Text, Number, Number, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Keyword.Namespace, Text, Number, Number, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]?)$'), bygroups(Keyword.Namespace, Text, Name.Variable, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]?)$'), bygroups(Keyword.Namespace, Text)),


            # manual fixes (order of proccessing)
            (r'^([\t ]+)(log-stderr|docroot|index)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),

            # ring keyword added on 2.2
            (r'^([\t ]+)(maxlen|format|size)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),

            (r'^([\t ]+)(log-stderr|log)([\t ]+)(global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Keywords that take a second keyword/option
            # no option
            (words(_haproxy_builtins.no_option_keywords, prefix=r'^([\t ]+)(no)([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Keyword.Reserved, Text, Name.Attribute)),

            # option
            (words(_haproxy_builtins.option_keywords, prefix=r'^([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Fcgi-app no option
            (words(_haproxy_builtins.fcgi_no_option_keywords, prefix=r'^([\t ]+)(no)([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Keyword.Reserved, Text, Name.Attribute)),

            # Fcgi-app option
            (words(_haproxy_builtins.fcgi_option_keywords, prefix=r'^([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # http-response
            (words(_haproxy_builtins.http_response, prefix=r'^([\t ]+)(http-response)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # http-request
            (words(_haproxy_builtins.http_request, prefix=r'^([\t ]+)(http-request)([\t ]+)', suffix='(?=[\t \n\r\(])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            (words(_haproxy_builtins.http_after_response, prefix=r'^([\t ]+)(http-after-response)([\t ]+)', suffix='(?=[\t \n\r\(])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),


            # tcp-check
            (r'^([\t ]+)(tcp-check)([\t ]+)(send-binary|expect|send|comment|connect)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # mailers
            (r'^([\t ]+)(mailer)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            (r'^([\t ]+)(mailer)', bygroups(Text, Keyword.Reserved)),
            (r'^([\t ]+)(email-alert)([\t ]+)(mailers|level|from|to)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # compression
            (r'^([\t ]+)(compression)([\t ]+)(algo|offload|type)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # stats
            (r'^([\t ]+)(stats)([\t ]+)(admin|auth|enable|hide-version|http-request|realm|refresh|scope|show-desc|show-legends|show-node|uri|socket|bind-process|timeout)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # mode
            (r'^([\t ]+)(mode)([\t ]+)(http|tcp|health)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # hold
            (r'^([\t ]+)(hold)([\t ]+)(other|refused|nx|timeout|valid|obsolete)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # timeout
            (r'^([\t ]+)(timeout)([\t ]+)(check|client-fin|client|connect|http-keep-alive|http-request|queue|server-fin|server|tarpit|tunnel)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # timeout Resolvers
            (r'^([\t ]+)(timeout)([\t ]+)(resolve|retry)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # balance
            (r'^([\t ]+)(balance)([\t ]+)(roundrobin|static-rr|leastconn|first|source|uri|queue|server-fin|server|tarpit|tunnel|random|rdp-cookie)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            (r'^([\t ]+)(balance)([\t ]+)(random)(?=[\(])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # Balance options
            # (r'^([\t ]+)(balance)([\t ]+)(roundrobin|static-rr|leastconn|first|source|uri|random|random|rdp-cookie)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # (r'^([\t ]+)(balance)([\t ]+)(random)(?=[\(])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # log
            (r'^([\t ]+)(log)([\t ]+)(stdout|stderr|global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Literal)),
            (r'^([\t ]+)(default-server)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # max-mind
            (r'^([\t ]+)(maxmind-update)([\t ]+)(url|cache|update|show|status|force-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            (r'^([\t ]+)(maxmind-cache-size|maxmind-debug|maxmind-load|maxmind-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # net aquity
            (r'^([\t ]+)(netacuity-cache-size|netacuity-debug|netacuity-property-separator|netacuity-load|netacuity-update|netacuity-test-ipv4)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # command
            (r'^([\t ]+)(command)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),

            #stick
            (r'^([\t ]+)(stick)([\t ]+)(match|on|store-request|store-response)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),




            # Rules for user in userlists
            # user <username> [password|insecure-password <password>] [groups <group>,<group>,(...)]

            (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s+)(groups)(\s+)(\S+)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text, Name.Attribute, Text, String )),

            (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            # Rules for group in userlists
            # group <groupname> [users <user>,<user>,(...)]

            (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            # Rules for capture
            (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)([\t ]+)(len)(\s)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String, Text, Name.Function)),
            (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String)),
            (r'^([\t ]+)(capture)([\t ]+)(cookie)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            (r'^([\t ]+)(capture)([\t ]+)(response|request)([\t ]+)(header)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute, Text, Name.Attribute)),

            # Rules for tcp-request
            (r'^([\t ]+)(tcp-request)([\t ]+)(connection|content|inspect-delay|session)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Rules for tcp-response
            (r'^([\t ]+)(tcp-response)([\t ]+)(content|inspect-delay)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Rules for http-check
            (r'^([\t ]+)(http-check)([\t ]+)(comment|connect|disable-on-404|expect|send-state|send|setvar)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),


            # Keywords that declare a variable
            # acl, use_backend, server, default_backend, table
            # Syntax: acl <acl-name>
            (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups( Text, Keyword.Declaration, Text, Name.Variable)),
            (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)(\S+)', bygroups( Text, Keyword.Declaration, Text, Error)),

            # Keywords that take a single value typically displayed as string
            # username        user
            # groupname       group
            # path            ca-base, chroot, crt-base, deviceatlas-json-file,h1-case-adjust-file, 51degrees-data-file, wurfl-data-file
            # name            deviceatlas-properties-cookie, group, localpeer, node
            # file            lua-load, pidfile
            # dir             server-state-base
            # file            server-state-file, ssl-dh-param-file
            # text            description
            # name            mailer peer table
            # id              nameserver
            # prefix          server-template
            # name            cookie
            # name            use-fcgi-app
            (r'^([\t ]+)(user|group|ca-base|chroot|cookie|crt-base|deviceatlas-json-file|h1-case-adjust-file|51degrees-data-file|wurfl-data-file|deviceatlas-properties-cookie|group|localpeer|node|lua-load|pidfile|server-state-base|server-state-file|ssl-dh-param-file|mailer|peer|table|nameserver|server-template|use-fcgi-app)([\t ]+)(\S+)', bygroups( Text, Keyword.Reserved, Text, String)),



            # userlist keywords
            (r'([\t ])(groups|users)', bygroups(Text, Name.Attribute)),


            # Global Parameters
            # RegEx:
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for global keywords (Group 2)
            (words(_haproxy_builtins.global_parameters, prefix=r'^([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved)),

            # Proxies
            # List of all proxy keywords from the one page documentation
            # Regex:
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for global keywords (Group 2)
            (words(_haproxy_builtins.proxy_keywords, prefix=r'^([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved)),

            # Bind options
            # Regex:
            # Look for whitespace (Group 1)
            # Look for bind option (Group 2)
            (words(_haproxy_builtins.bind_options, prefix=r'([\t ])', suffix='(?=[\t \n\r])'), bygroups(Text, Name.Attribute)),

            # Server & Default Server options
            # Regex:
            # Look for whitespace (Group 1)
            # Look for server and default server option (Group 2)
            (words(_haproxy_builtins.server_options, prefix=r'([\t ])', suffix='(?=[\t \n\r])'), bygroups(Text, Name.Attribute)),



            #manual fix
            (r'([\t ])(track-sc0|track-sc1|track-sc2)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),


            # Resolvers keywords
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for resolvers keywords (Group 2)
            (r'^([\t ]+)(accepted_payload_size|nameserver|parse-resolv-conf|hold|resolve_retries|timeout)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),
            # Cache keywords
            (r'^([\t ]+)(total-max-size|max-object-size|max-age)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),
            # ACL
            # ACL Matches
            # ACL Converters
            # ACL Fetches
            # ACL Predefined
            # Filters
            # Fast CGI
            (r'^([\t ]+)(path-info)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),

            # functions
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(\S+)(\s+)(})', bygroups(Text, Name.Function, Text, String, Text, Text)),
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(.+)$', bygroups(Text, Name.Function, Text, String)),
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(?=[\t \n\r])', bygroups(Text, Name.Function)),

            (r'([\t ])(url_beg|url_dir|url_dom|url_end|url_len|url_reg|url_sub|url)(\s+)(\S+)(\s+)(})', bygroups(Text, Name.Function, Text, String, Text, Text)),
            (r'([\t ])(url_beg|url_dir|url_dom|url_end|url_len|url_reg|url_sub|url)(\s+)(.+)$', bygroups(Text, Name.Function, Text, String)),
            (r'([\t ])(url_beg|url_dir|url_dom|url_end|url_len|url_reg|url_sub|url)(?=[\t \n\r])', bygroups(Text, Name.Function)),

            (r'([\t ])(addr)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'([\t ])(verify|none|crt|tfo|check-ssl|check|alpn)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'([\t ])(accept-netscaler-cip|accept-proxy|allow-0rtt|alpn|backlog|ca-file|ca-ignore-err|ca-sign-file|ca-sign-pass|ciphers|ciphersuites|crl-file|crt|crt-ignore-err|crt-list|curves|defer-accept|ecdhe|expose-fd listeners|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|generate-certificates|gid|group|id|interface|level|maxconn|mode|mss|namespace|name|nice|no-ca-names|no-sslv3|no-tls-tickets|no-tlsv10|no-tlsv11|no-tlsv12|no-tlsv13|npn|prefer-client-ciphers|process|proto|severity-output|ssl-max-ver|ssl-min-ver|ssl_fc|ssl|strict-sni|tcp-ut|tfo|tls-ticket-keys|transparent|uid|user|v4v6|v6only|verify)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'(\s)(location|scheme|prefix|random)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'(\,|[\t ])(type|size|store)(?=[\t \n\r])', bygroups(Text, Name.Function)),

            (r'(\,|[\t ])(len|expire)(?=[\t \n\r])', bygroups(Text, Name.Function)),
            # types
            (r'(\,|[\t ])(string|integer|ipv6|ip|binary)(?=[\t \n\r])', bygroups(Text, Keyword.Type)),

            (r'([\t ])(SSLv3|TLSv1.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)(?=[\t \n\r])', bygroups(Text, Literal)),
            (r'([\t ])(conn-failure|empty-response|junk-response|response-timeout|0rtt-rejected|except|nbsrv)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),

            # stick table functions
            (r'(\,|[\t ])(gpc0|gpc1|conn_cnt|conn_cur|sess_cnt|http_req_cnt|http_err_cnt|bytes_in_cnt|bytes_out_cnt)(?=[\,\t \n\r])', bygroups(Text, Name.Function)),
            (r'(\,|[\t ])(gpc0_rate|gpc1_rate|conn_rate|sess_rate|http_req_rate|http_err_rate|bytes_in_rate|bytes_out_rate)(?=[\(|\s])', bygroups(Text, Name.Function)),

            (r'(?<=[\t ])(table)(?=[\t \n\r])', bygroups(Name.Attribute)),

            # Converter functions
            (words(_haproxy_builtins.converter_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Converters
            (words(_haproxy_builtins.converters, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetches internal states functions
            (words(_haproxy_builtins.internal_states_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetches internal states
            (words(_haproxy_builtins.internal_states_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 4 functions
            (words(_haproxy_builtins.l4_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 4
            (words(_haproxy_builtins.l4_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 5 functions
            (words(_haproxy_builtins.l5_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 5
            (words(_haproxy_builtins.l5_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples from buffer contents (Layer 6) functions
            (words(_haproxy_builtins.l6_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetching samples from buffer contents (Layer 6)
            (words(_haproxy_builtins.l6_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching HTTP samples (Layer 7) functions
            (words(_haproxy_builtins.l7_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetching HTTP samples (Layer 7)
            (words(_haproxy_builtins.l7_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples for developers Functions
            (words(_haproxy_builtins.dev_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='(?=[\(|\s])'), bygroups(Text, Name.Function)),

            # Fetching samples for developers
            (words(_haproxy_builtins.dev_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # ACL Predefined functions
            (r'(\,|[\t ])(FALSE|HTTP_1\.0|HTTP_1\.1|HTTP_CONTENT|HTTP_URL_ABS|HTTP_URL_SLASH|HTTP_URL_STAR|HTTP|LOCALHOST|METH_CONNECT|METH_DELETE|METH_GET|METH_HEAD|METH_OPTIONS|METH_POST|METH_PUT|METH_TRACE|RDP_COOKIE|REQ_CONTENT|TRUE|WAIT_END)(?=[\t \n\r]|\,)', bygroups(Text, Name.Attribute)),

            # ACL conditionals
            (r'(\s)(if|unless)(\s+)([a-zA-Z0-9_-]+|!\s?[a-zA-Z0-9_-]+)', bygroups(Text, Operator.Word, Text, Name.Variable)),
            (r'\b(if|unless)\b', Operator.Word),
            # Logical operators
            (r'(?<=\s)(lt|gt|or|\|\||!)', bygroups(Operator.Word)),

            # Numbers
            # also optional letter supported, like '100s'
            (r'(?<=[\t \(\,])([0-9]+)(?=[\t \r\n\)\,])', bygroups(Number)),
            (r'(?<=[\t \(\,])([0-9]+)(k|ms|s|m|h|w|y)(?=[\t \r\n\)\,])', bygroups( Literal.Number, Literal.Number)),
            # IP address/subnet
            # ([\t ]|,)[0-9]+(?:\.[0-9]+){3}(\/[0-9]+)?
            (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(\/[0-9]+)?', bygroups(Text, Literal.Number, Number)),
            # IP address:port
            (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(:[0-9]+)?', bygroups(Text, Literal.Number, Number)),

            # Ports only
            (r'(:+)([0-9]+)', bygroups(Text, Literal.Number)),
            (r'(\*)(:+)([0-9]+)',bygroups(Operator ,Text, Literal.Number)),
            # Remaining text
            (r'.', Text)



            # # HAProxy configuration parsing basics.
            # # A typical file is split into sections
            # # To declare a section you need to use its keyword at the start of the line.
            # # Only sections and comments are allowed at the start of the line.
            # # Configuration keywords always start with indentation either by space or tabs or a mix of the two.
            # # Comment that starts at the beginning of the line
            # # Regex:
            # # Start at the start of the line
            # # Look for a #
            # # Grab everything till the end of line
            # (r'^#.*$', Comment.Singleline),
            # # Inline comment
            # # Regex:
            # # Look for whitespace followed by #
            # # Grab everything till the end of line
            # (r'(?<=\s)#.*$', Comment.Singleline),
            # # Path
            # (r'(\s)(\/\S+)', bygroups(Text, String)),
            # # Path at the end of the line
            # (r'(\s)(\/\S+)$', bygroups(Text, String)),
            # # Urls
            # (r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', String),
            # # # Curly Braces
            # # (r'({)(.*?)(})', bygroups(String, Text, String)),
            # # Strings
            # (r'(\".*?\")', bygroups(String.Double)),
            #
            #
            # # dashed options
            # (r'(?<=\s)(-)(m|i)(?=\s)', bygroups(Text, Name.Attribute)),
            #
            #
            # # Main Sections
            # # RegEx:
            # # Start at the start of the line
            # # Look for any of the keywords (Group 1)
            # # Look for whitespace - matches 0 or more (Group 2)
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)([\t ]+)(\S+)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$', bygroups(Name.Namespace, Text, Name.Variable, Text, Number, Number, Text)),
            #
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$', bygroups(Name.Namespace, Text, Number, Number, Text)),
            #
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)([\t ]+)(\S+)([\t ]?)$', bygroups(Name.Namespace, Text, Name.Variable, Text)),
            #
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)([\t ]?)$', bygroups(Name.Namespace, Text)),
            #
            # # Start at the start of the line
            # # Look for any of the keywords (Group 1)
            # # Look for whitespace - matches 0 or more (Group 2)
            # # Grab everything else (Group 3)
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)(\s?)(.*)$', bygroups(Name.Namespace, Text, Name.Variable)),
            #
            #
            # # manual fixes (ordering)
            # (r'^([\t ]+)(log-stderr|docroot|index)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            #
            # (r'^([\t ]+)(log-stderr|log)([\t ]+)(global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            #
            #
            #
            # # Keywords that take a second keyword/option
            # # no option
            # (r'^([\t ]+)(no)([\t ]+)(option)([\t ]+)(abortonclose|accept-invalid-http-request|accept-invalid-http-response|allbackups|checkcache|clitcpka|contstats|dontlog-normal|dontlognull|h1-case-adjust-bogus-client|h1-case-adjust-bogus-server|http-buffer-request|http-ignore-probes|http-keep-alive|http-no-delay|http-pretend-keepalive|http-server-close|http-use-proxy-header|httpclose|http_proxy|independent-streams|log-separate-errors|logasap|nolinger|persist|prefer-last-server|redispatch|socket-stats|splice-auto|splice-request|splice-response|srvtcpka|tcp-smart-accept|tcp-smart-connect|transparent)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Keyword.Reserved, Text, Name.Attribute)),
            # # option
            # (r'^([\t ]+)(option)([\t ]+)(abortonclose|accept-invalid-http-request|accept-invalid-http-response|allbackups|checkcache|clitcpka|contstats|dontlog-normal|dontlognull|forwardfor|h1-case-adjust-bogus-client|h1-case-adjust-bogus-server|http-buffer-request|http-ignore-probes|http-keep-alive|http-no-delay|http-pretend-keepalive|http-server-close|http-use-proxy-header|httpchk|httpclose|httplog|http_proxy|independent-streams|ldap-check|external-check|no\s+log-health-checks|log-health-checks|log-separate-errors|logasap|mysql-check|nolinger|originalto|persist|pgsql-check|smtp-check|prefer-last-server|redispatch|redis-check|smtpchk|socket-stats|splice-auto|splice-request|splice-response|spop-check|srvtcpka|ssl-hello-chk|tcp-check|tcp-smart-accept|tcp-smart-connect|tcpka|tcplog|transparent)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # http-response
            # (r'^([\t ]+)(http-response)([\t ]+)(add-acl|add-header|allow|cache-store|capture|del-acl|del-header|del-map|deny|redirect|replace-header|replace-value|return|sc-inc-gpc0|sc-inc-gpc1|sc-set-gpt0|send-spoe-group|set-header|set-log-level|set-map|set-mark|set-nice|set-status|set-tos|set-var|silent-drop|strict-mode|track-sc0|track-sc1|track-sc2|unset-var)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # http-request
            # (r'^([\t ]+)(http-request)([\t ]+)(add-acl|add-header|allow|auth|cache-use|capture|del-acl|del-header|del-map|deny|disable-l7-retry|do-resolve|early-hint|redirect|reject|replace-header|replace-path|replace-uri|replace-value|return|sc-inc-gpc0|sc-inc-gpc1|sc-set-gpt0|set-dst-port|set-dst|set-header|set-log-level|set-map|set-mark|set-method|set-nice|set-path|set-priority-class|set-priority-offset|set-query|set-src-port|set-src|set-tos|set-uri|set-var|send-spoe-group|silent-drop|strict-mode|tarpit|track-sc0|track-sc2|track-sc3|unset-var|use-service|wait-for-handshake)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # tcp-check
            # (r'^([\t ]+)(tcp-check)([\t ]+)(send-binary|expect|send|comment|connect)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # mailers
            # (r'^([\t ]+)(mailer)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            # # mailers
            # (r'^([\t ]+)(mailer)', bygroups(Text, Keyword.Reserved)),
            # (r'^([\t ]+)(email-alert)([\t ]+)(mailers|level|from|to)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # compression
            # (r'^([\t ]+)(compression)([\t ]+)(algo|offload|type)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # stats
            # (r'^([\t ]+)(stats)([\t ]+)(admin|auth|enable|hide-version|http-request|realm|refresh|scope|show-desc|show-legends|show-node|uri|socket|bind-process|timeout)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # mode
            # (r'^([\t ]+)(mode)([\t ]+)(http|tcp|health)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # hold
            # (r'^([\t ]+)(hold)([\t ]+)(other|refused|nx|timeout|valid|obsolete)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # timeout
            # (r'^([\t ]+)(timeout)([\t ]+)(check|client-fin|client|connect|http-keep-alive|http-request|queue|server-fin|server|tarpit|tunnel)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # timeout Resolvers
            # (r'^([\t ]+)(timeout)([\t ]+)(resolve|retry)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # balance
            # (r'^([\t ]+)(balance)([\t ]+)(roundrobin|static-rr|leastconn|first|source|uri|queue|server-fin|server|tarpit|tunnel)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # log
            # (r'^([\t ]+)(log)([\t ]+)(stdout|stderr|global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Literal)),
            # (r'^([\t ]+)(default-server)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # # max-mind
            # (r'^([\t ]+)(maxmind-update)([\t ]+)(url|cache|update|show|status|force-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # (r'^([\t ]+)(maxmind-cache-size|maxmind-debug|maxmind-load|maxmind-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # # net aquity
            # (r'^([\t ]+)(netacuity-cache-size|netacuity-debug|netacuity-property-separator|netacuity-load|netacuity-update|netacuity-test-ipv4)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # # command
            # (r'^([\t ]+)(command)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            #
            # #stick
            # (r'^([\t ]+)(stick)([\t ]+)(match|on|store-request|store-response)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            #
            #
            #
            # # Rules for user in userlists
            # # user <username> [password|insecure-password <password>] [groups <group>,<group>,(...)]
            #
            # (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s+)(groups)(\s+)(\S+)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text, Name.Attribute, Text, String )),
            #
            # (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),
            #
            # # Rules for group in userlists
            # # group <groupname> [users <user>,<user>,(...)]
            #
            # (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),
            #
            # (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),
            #
            # # Rules for capture
            # (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)([\t ]+)(len)(\s)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String, Text, Name.Function)),
            # (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String)),
            # (r'^([\t ]+)(capture)([\t ]+)(cookie)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            # (r'^([\t ]+)(capture)([\t ]+)(response|request)([\t ]+)(header)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute, Text, Name.Attribute)),
            #
            # # Rules for tcp-request
            # (r'^([\t ]+)(tcp-request)([\t ]+)(connection|content|inspect-delay|session)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            # # Rules for tcp-response
            # (r'^([\t ]+)(tcp-response)([\t ]+)(content|inspect-delay)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            # # Rules for http-check
            # (r'^([\t ]+)(http-check)([\t ]+)(disable-on-404|expect|send-state|send)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            #
            #
            # # Keywords that declare a variable
            # # acl, use_backend, server, default_backend, table
            # # Syntax: acl <acl-name>
            # (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved, Text, Name.Variable)),
            # (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)(\S+)', bygroups( Text, Keyword.Reserved, Text, Error)),
            #
            # # Keywords that take a single value typically displayed as string
            # # username        user
            # # groupname       group
            # # path            ca-base, chroot, crt-base, deviceatlas-json-file,h1-case-adjust-file, 51degrees-data-file, wurfl-data-file
            # # name            deviceatlas-properties-cookie, group, localpeer, node
            # # file            lua-load, pidfile
            # # dir             server-state-base
            # # file            server-state-file, ssl-dh-param-file
            # # text            description
            # # name            mailer peer table
            # # id              nameserver
            # # prefix          server-template
            # # name            cookie
            # # name            use-fcgi-app
            # (r'^([\t ]+)(user|group|ca-base|chroot|cookie|crt-base|deviceatlas-json-file|h1-case-adjust-file|51degrees-data-file|wurfl-data-file|deviceatlas-properties-cookie|group|localpeer|node|lua-load|pidfile|server-state-base|server-state-file|ssl-dh-param-file|description|mailer|peer|table|nameserver|server-template|use-fcgi-app)([\t ]+)(\S+)', bygroups( Text, Keyword.Reserved, Text, String)),
            #
            # # userlist keywords
            # (r'([\t ])(groups|users)', bygroups(Text, Name.Attribute)),
            #
            #
            # # Global Parameters
            # # RegEx:
            # # Start at the start of the line
            # # Look for whitespace - matches at least 1 char or more (Group 1)
            # # Look for global keywords (Group 2)
            # (r'^([\t ]+)(master-worker|ca-base|chroot|crt-base|cpu-map|daemon|description|deviceatlas-json-file|deviceatlas-log-level|deviceatlas-separator|deviceatlas-properties-cookie|external-check|gid|group|hard-stop-after|h1-case-adjust|h1-case-adjust-file|localpeer|log-format|log-tag|log-send-hostname|log|lua-load|lua-prepend-path|mworker-max-reloads|nbproc|nbthread|node|pidfile|presetenv|resetenv|uid|ulimit-n|user|set-dumpable|setenv|stats|ssl-default-bind-ciphers|ssl-default-bind-ciphersuites|ssl-default-bind-options|ssl-default-server-ciphers|ssl-default-server-ciphersuites|ssl-default-server-options|ssl-dh-param-file|ssl-server-verify|unix-bind|unsetenv|51degrees-update|51degrees-data-file|51degrees-property-name-list|51degrees-property-separator|51degrees-cache-size|wurfl-update|wurfl-data-file|wurfl-information-list|wurfl-information-list-separator|wurfl-cache-size|strict-limits|busy-polling|max-spread-checks|maxconn|maxconnrate|maxcomprate|maxcompcpuusage|maxpipes|maxsessrate|maxsslconn|maxsslrate|maxzlibmem|noepoll|nokqueue|noevports|nopoll|nosplice|nogetaddrinfo|noreuseport|profiling\.tasks|spread-checks|server-state-base|server-state-file-base|server-state-file|ssl-engine|ssl-mode-async|tune\.buffers\.limit|tune\.buffers\.reserve|tune\.bufsize|tune\.chksize|tune\.comp\.maxlevel|tune\.h2\.header-table-size|tune\.h2\.initial-window-size|tune\.h2\.max-concurrent-streams|tune\.http\.cookielen|tune\.http\.logurilen|tune\.http\.maxhdr|tune\.idletimer|tune\.lua\.forced-yield|tune\.lua\.maxmem|tune\.lua\.session-timeout|tune\.lua\.task-timeout|tune\.lua\.service-timeout|tune\.maxaccept|tune\.maxpollevents|tune\.maxrewrite|tune\.pattern\.cache-size|tune\.pipesize|tune\.pool-high-fd-ratio|tune\.pool-low-fd-ratio|tune\.rcvbuf\.client|tune\.rcvbuf\.server|tune\.recv_enough|tune\.runqueue-depth|tune\.sndbuf\.client|tune\.sndbuf\.server|tune\.ssl\.cachesize|tune\.ssl\.lifetime|tune\.ssl\.force-private-cache|tune\.ssl\.maxrecord|tune\.ssl\.default-dh-param|tune\.ssl\.ssl-ctx-cache-size|tune\.ssl\.capture-cipherlist-size|tune\.vars\.global-max-size|tune\.vars\.proc-max-size|tune\.vars\.reqres-max-size|tune\.vars\.sess-max-size|tune\.vars\.txn-max-size|tune\.zlib\.memlevel|tune\.zlib\.windowsize|debug|quiet|module-path|module-load|send-metrics-url|send-metrics-header|send-metrics-content-type|send-metrics-data|send-metrics-debug|update)', bygroups( Text, Keyword.Reserved)),
            #
            #
            #
            #
            # # Proxies
            # # List of all proxy keywords from the one page documentation
            # # Regex:
            # # Start at the start of the line
            # # Look for whitespace - matches at least 1 char or more (Group 1)
            # # Look for global keywords (Group 2)
            # (r'^([\t ]+)(acl|backlog|balance|bind-process|bind|capture|compression|cookie|declare|default-server|default_backend|description|disabled|dispatch|email-alert|enabled|errorfiles|errorfile|errorloc303|errorloc302|errorloc|force-persist|filter|fullconn|grace|hash-type|http-after-response|http-check|http-request|http-response|http-reuse|http-send-name-header|id|ignore-persist|load-server-state-from-file|log-format-sd|log-format|log-tag|log|max-keep-alive-queue|maxconn|mode|monitor-uri|monitor-net|monitor|option|external-check|persist|rate-limit|redirect|retries|retry-on|server-state-file-name|server-template|server|source|stats|stick-table|stick|tcp-check|tcp-request|tcp-response|timeout|transparent|unique-id-format|unique-id-header|use_backend|use-fcgi-app|use-server)', bygroups( Text, Keyword.Reserved)),
            # # Bind options
            # # Regex:
            # # Look for whitespace (Group 1)
            # # Look for bind option (Group 2)
            # (r'([\t ])(accept-netscaler-cip|accept-proxy|allow-0rtt|alpn|backlog|ca-file|ca-ignore-err|ca-sign-file|ca-sign-pass|ciphers|ciphersuites|crl-file|crt|crt-ignore-err|crt-list|curves|defer-accept|ecdhe|expose-fd listeners|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|generate-certificates|gid|group|id|interface|level|maxconn|mode|mss|namespace|name|nice|no-ca-names|no-sslv3|no-tls-tickets|no-tlsv10|no-tlsv11|no-tlsv12|no-tlsv13|npn|prefer-client-ciphers|process|proto|severity-output|ssl-max-ver|ssl-min-ver|ssl_fc|ssl|strict-sni|tcp-ut|tfo|tls-ticket-keys|transparent|uid|user|v4v6|v6only|verify)', bygroups(Text, Name.Attribute)),
            # # Server & Default Server options
            # # Regex:
            # # Look for whitespace (Group 1)
            # # Look for server and default server option (Group 2)
            #
            # #manual fix
            # (r'([\t ])(track-sc0|track-sc1|track-sc2)', bygroups(Text, Name.Attribute)),
            #
            # (r'([\t ])(addr|agent-check|agent-send|agent-inter|agent-addr|agent-port|allow-0rtt|alpn|backup|ca-file|check-send-proxy|check-alpn|check-sni|check-ssl|check-via-socks4|check|ciphers|ciphersuites|cookie|crl-file|crt|disabled|enabled|error-limit|fall|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|id|init-addr|inter|fastinter|downinter|maxconn|maxqueue|max-reuse|minconn|namespace|no-agent-check|no-backup|no-check-ssl|no-check|no-send-proxy-v2-ssl-cn|no-send-proxy-v2-ssl|no-send-proxy-v2|no-send-proxy|no-sslv3|no-ssl-reuse|no-ssl|no-tls-tickets|no-tlsv13|no-tlsv12|no-tlsv11|no-tlsv10|no-verifyhost|no-tfo|non-stick|npn|observe|on-error|on-marked-down|on-marked-up|pool-max-conn|pool-purge-delay|port|proto|redir|rise|resolvers|resolve-opts|resolve-prefer|resolve-net|send-proxy-v2|send-proxy|proxy-v2-options|send-proxy-v2-ssl-cn|send-proxy-v2-ssl|slowstart|sni|source|ssl-max-ver|ssl-min-ver|ssl-reuse|ssl|stick|socks4|tcp-ut|tfo|track|tls-tickets|verifyhost|verify|weight)', bygroups(Text, Name.Attribute)),
            # # Resolvers keywords
            # # Start at the start of the line
            # # Look for whitespace - matches at least 1 char or more (Group 1)
            # # Look for resolvers keywords (Group 2)
            # (r'^([\t ]+)(accepted_payload_size|nameserver|parse-resolv-conf|hold|resolve_retries|timeout)', bygroups( Text, Keyword.Reserved)),
            # # Cache keywords
            # (r'^([\t ]+)(total-max-size|max-object-size|max-age)', bygroups( Text, Keyword.Reserved)),
            # # ACL
            # # ACL Matches
            # # ACL Converters
            # # ACL Fetches
            # # ACL Predefined
            # # Filters
            # # Fast CGI
            # (r'^([\t ]+)(path-info)', bygroups( Text, Keyword.Reserved)),
            #
            #
            #
            # # functions
            # (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(\S+)(\s+)(})', bygroups(Text, Name.Function, Text, String, Text, Text)),
            # (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(.+)$', bygroups(Text, Name.Function, Text, String)),
            # (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)', bygroups(Text, Name.Function)),
            # (r'([\t ])(addr)', bygroups(Text, Name.Attribute)),
            # (r'([\t ])(verify|none|crt|tfo|check-ssl|check|alpn)', bygroups(Text, Name.Attribute)),
            # (r'([\t ])(accept-netscaler-cip|accept-proxy|allow-0rtt|alpn|backlog|ca-file|ca-ignore-err|ca-sign-file|ca-sign-pass|ciphers|ciphersuites|crl-file|crt|crt-ignore-err|crt-list|curves|defer-accept|ecdhe|expose-fd listeners|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|generate-certificates|gid|group|id|interface|level|maxconn|mode|mss|namespace|name|nice|no-ca-names|no-sslv3|no-tls-tickets|no-tlsv10|no-tlsv11|no-tlsv12|no-tlsv13|npn|prefer-client-ciphers|process|proto|severity-output|ssl-max-ver|ssl-min-ver|ssl_fc|ssl|strict-sni|tcp-ut|tfo|tls-ticket-keys|transparent|uid|user|v4v6|v6only|verify)', bygroups(Text, Name.Attribute)),
            # (r'(\s)(location|scheme|prefix|random)', bygroups(Text, Name.Attribute)),
            # (r'(\,|[\t ])(type|string|size|store|http_req_rate|http_req_cnt)', bygroups(Text, Name.Function)),
            #
            # (r'([\t ])(SSLv3|TLSv1.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)', bygroups(Text, Literal)),
            # (r'([\t ])(conn-failure|empty-response|junk-response|response-timeout|0rtt-rejected|except|nbsrv)', bygroups(Text, Name.Attribute)),
            #
            # # Converter functions
            # (r'(\,|[\t ])(51d\.single|add|aes_gcm_dec|and|bytes|concat|crc32|crc32c|da-csv-conv|debug|div|djb2|field|http_date|in_table|json|language|ltime|map|mod|mul|or|protobuf|regsub|capture-req|capture-res|sdbm|sha2|strcmp|sub|table_bytes_in_rate|table_bytes_out_rate|table_conn_cnt|table_conn_cur|table_conn_rate|table_gpt0|table_gpc0|table_gpc0_rate|table_gpc1|table_gpc1_rate|table_http_err_cnt|table_http_err_rate|table_http_req_cnt|table_http_req_rate|table_kbytes_in|table_kbytes_out|table_server_id|table_sess_cnt|table_sess_rate|table_trackers|url_dec|ungrpc|utime|word|wt6|xor|xxh32|xxh64)([\(|\s])', bygroups(Text, Name.Function, Text)),
            # # Converters
            # (r'(\,|[\t ])(b64dec|base64|bool|cpl|even|hex|hex2i|length|lower|nbsrv|neg|not|odd|sha1|srv_queue|upper)', bygroups(Text, Name.Function)),
            #
            # # Fetches internal states functions
            # (r'(\,|[\t ])(avg_queue|be_conn|be_conn_free|be_sess_rate|bin|bool|connslots|date|distcc_body|distcc_param|env|fe_conn|fe_req_rate|fe_sess_rate|int|ipv4|ipv6|meth|nbsrv|queue|rand|uuid|srv_conn|srv_conn_free|srv_is_up|srv_queue|srv_sess_rate|str|table_avl|table_cnt|var)([\(|\s])', bygroups(Text, Name.Function, Text)),
            # # Fetches internal states
            # (r'(\,|[\t ])(always_false|always_true|cpu_calls|cpu_ns_avg|cpu_ns_tot|date_us|hostname|lat_ns_avg|lat_ns_tot|nbproc|prio_class|prio_offset|proc|stopping|thread)', bygroups(Text, Name.Function)),
            #
            # # Fetching samples at Layer 4 functions
            # (r'(\,|[\t ])(fc_rtt|fc_rttvar|sc_bytes_in_rate|sc0_bytes_in_rate|sc1_bytes_in_rate|sc2_bytes_in_rate|sc_bytes_out_rate|sc0_bytes_out_rate|sc1_bytes_out_rate|sc2_bytes_out_rate|sc_clr_gpc0|sc0_clr_gpc0|sc1_clr_gpc0|sc2_clr_gpc0|sc_clr_gpc1|sc0_clr_gpc1|sc1_clr_gpc1|sc2_clr_gpc1|sc_conn_cnt|sc0_conn_cnt|sc1_conn_cnt|sc2_conn_cnt|sc_conn_cur|sc0_conn_cur|sc1_conn_cur|sc2_conn_cur|sc_conn_rate|sc0_conn_rate|sc1_conn_rate|sc2_conn_rate|sc_get_gpc0|sc0_get_gpc0|sc1_get_gpc0|sc2_get_gpc0|sc_get_gpc1|sc0_get_gpc1|sc1_get_gpc1|sc2_get_gpc1|sc_get_gpt0|sc0_get_gpt0|sc1_get_gpt0|sc2_get_gpt0|sc_gpc0_rate|sc0_gpc0_rate|sc1_gpc0_rate|sc2_gpc0_rate|sc_gpc1_rate|sc0_gpc1_rate|sc1_gpc1_rate|sc2_gpc1_rate|sc_http_err_cnt|sc0_http_err_cnt|sc1_http_err_cnt|sc2_http_err_cnt|sc_http_err_rate|sc0_http_err_rate|sc1_http_err_rate|sc2_http_err_rate|sc_http_req_cnt|sc0_http_req_cnt|sc1_http_req_cnt|sc2_http_req_cnt|sc_http_req_rate|sc0_http_req_rate|sc1_http_req_rate|sc2_http_req_rate|sc_inc_gpc0|sc0_inc_gpc0|sc1_inc_gpc0|sc2_inc_gpc0|sc_inc_gpc1|sc0_inc_gpc1|sc1_inc_gpc1|sc2_inc_gpc1|sc_kbytes_in|sc0_kbytes_in|sc1_kbytes_in|sc2_kbytes_in|sc_kbytes_out|sc0_kbytes_out|sc1_kbytes_out|sc2_kbytes_out|sc_sess_cnt|sc0_sess_cnt|sc1_sess_cnt|sc2_sess_cnt|sc_sess_rate|sc0_sess_rate|sc1_sess_rate|sc2_sess_rate|sc_tracked|sc0_tracked|sc1_tracked|sc2_tracked|sc_trackers|sc0_trackers|sc1_trackers|sc2_trackers|src_bytes_in_rate|src_bytes_out_rate|src_clr_gpc0|src_clr_gpc1|src_conn_cnt|src_conn_cur|src_conn_rate|src_get_gpc0|src_get_gpc1|src_get_gpt0|src_gpc0_rate|src_gpc1_rate|src_http_err_cnt|src_http_err_rate|src_http_req_cnt|src_http_req_rate|src_inc_gpc0|src_inc_gpc1|src_kbytes_in|src_kbytes_out|src_sess_cnt|src_sess_rate|src_updt_conn_cnt)([\(|\s])', bygroups(Text, Name.Function, Text)),
            #
            # # Fetching samples at Layer 4
            # (r'(\,|[\t ])(bc_http_major|be_id|be_name|dst|dst_conn|dst_is_local|dst_port|fc_http_major|fc_pp_authority|fc_rcvd_proxy|fc_unacked|fc_sacked|fc_retrans|fc_fackets|fc_lost|fc_reordering|fe_defbe|fe_id|fe_name|so_id|so_name|src|src_is_local|src_port|srv_id|srv_name)', bygroups(Text, Name.Function)),
            #
            # # Fetching samples at Layer 5 functions
            # (r'(\,|[\t ])(51d\.all|ssl_c_i_dn|ssl_c_s_dn|ssl_f_i_dn|ssl_f_s_dn)([\(|\s])', bygroups(Text, Name.Function, Text)),
            #
            # # Fetching samples at Layer 5
            # (r'(\,|[\t ])(ssl_bc_alg_keysize|ssl_bc_alpn|ssl_bc_cipher|ssl_bc_client_random|ssl_bc_is_resumed|ssl_bc_npn|ssl_bc_protocol|ssl_bc_unique_id|ssl_bc_server_random|ssl_bc_session_id|ssl_bc_session_key|ssl_bc_use_keysize|ssl_bc|ssl_c_ca_err|ssl_c_ca_err_depth|ssl_c_der|ssl_c_err|ssl_c_key_alg|ssl_c_notafter|ssl_c_notbefore|ssl_c_serial|ssl_c_sha1|ssl_c_sig_alg|ssl_c_used|ssl_c_verify|ssl_c_version|ssl_f_der|ssl_f_key_alg|ssl_f_notafter|ssl_f_notbefore|ssl_f_serial|ssl_f_sha1|ssl_f_sig_alg|ssl_f_version|ssl_fc_alg_keysize|ssl_fc_alpn|ssl_fc_cipherlist_bin|ssl_fc_cipherlist_hex|ssl_fc_cipherlist_str|ssl_fc_cipherlist_xxh|ssl_fc_cipher|ssl_fc_client_random|ssl_fc_has_crt|ssl_fc_has_early|ssl_fc_has_sni|ssl_fc_is_resumed|ssl_fc_npn|ssl_fc_protocol|ssl_fc_unique_id|ssl_fc_server_random|ssl_fc_session_id|ssl_fc_session_key|ssl_fc_sni|ssl_fc_use_keysize|ssl_fc)', bygroups(Text, Name.Function)),
            #
            # # Fetching samples from buffer contents (Layer 6) functions
            # (r'(\,|[\t ])(payload_lv|payload|req\.payload|req\.payload_lv|req\.rdp_cookie|rdp_cookie|req\.rdp_cookie_cnt|rdp_cookie_cnt|res\.payload_lv|res\.payload)([\(|\s])', bygroups(Text, Name.Function, Text)),
            #
            # # Fetching samples from buffer contents (Layer 6)
            # (r'(\,|[\t ])(req\.hdrs_bin|req\.hdrs|req\.len|req\.proto_http|req\.ssl_alpn|req\.ssl_ec_ext|req\.ssl_hello_type|req\.ssl_sni|req\.ssl_st_ext|req\.ssl_ver|res\.len|res\.ssl_hello_type|wait_end|req_proto_http|req_ssl_hello_type|req_ssl_sni|req_ssl_ver|rep_ssl_hello_type|req_len)', bygroups(Text, Name.Function)),
            #
            #
            # # Fetching HTTP samples (Layer 7) functions
            # (r'(\,|[\t ])(capture\.req\.hdr|capture\.res\.hdr|req\.body_param|req\.cook|cook|req\.cook_cnt|cook_cnt|req\.cook_val|cook_val|cookie|hdr|req\.fhdr|req\.fhdr_cnt|req\.hdr|req\.hdr_cnt|hdr_cnt|req\.hdr_ip|hdr_ip|req\.hdr_val|hdr_val|http_auth|http_auth_group|req\.hdr_names|res\.cook|scook|res\.cook_cnt|scook_cnt|res\.cook_val|scook_val|res\.fhdr|res\.fhdr_cnt|res\.hdr|shdr|res\.hdr_cnt|shdr_cnt|res\.hdr_ip|shdr_ip|res\.hdr_names|res\.hdr_val|shdr_val|urlp|url_param|urlp_val|set-cookie)([\(|\s])', bygroups(Text, Name.Function, Text)),
            # #
            #
            # # Fetching HTTP samples (Layer 7)
            # (r'(\,|[\t ])(base32\+src|base32|base|capture\.req\.method|capture\.req\.uri|capture\.req\.ver|capture\.res\.ver|req\.body|req\.body_len|req\.body_size|http_auth_pass|http_auth_type|http_auth_user|http_first_req|method|path|query|req\.ver|req_ver|res\.comp|res\.comp_algo|res\.ver|resp_ver|status|unique-id|url|url_ip|url_port|url32|url32+src)', bygroups(Text, Name.Function)),
            #
            # # Fetching samples for developers Functions
            # (r'(\,|[\t ])(internal\.htx_blk\.size|internal\.htx_blk\.type|internal\.htx_blk\.data|internal\.htx_blk\.hdrname|internal\.htx_blk\.hdrval|internal\.htx_blk\.start_line)([\(|\s])', bygroups(Text, Name.Function, Text)),
            #
            # # Fetching samples for developers
            # (r'(\,|[\t ])(internal\.htx\.data|internal\.htx\.free|internal\.htx\.free_data|internal\.htx\.has_eom|internal\.htx\.nbblks|internal\.htx\.size|internal\.htx\.used|internal\.strm\.is_htx)', bygroups(Text, Name.Function)),
            #
            #
            #
            #
            # # ACL Predefined functions
            # (r'(\,|[\t ])(FALSE|HTTP_1\.0|HTTP_1\.1|HTTP_CONTENT|HTTP_URL_ABS|HTTP_URL_SLASH|HTTP_URL_STAR|HTTP|LOCALHOST|METH_CONNECT|METH_DELETE|METH_GET|METH_HEAD|METH_OPTIONS|METH_POST|METH_PUT|METH_TRACE|RDP_COOKIE|REQ_CONTENT|TRUE|WAIT_END)', bygroups(Text, Name.Attribute)),
            #
            # # ACL conditionals
            # (r'(\s)(if|unless)(\s+)([a-zA-Z0-9_-]+|!\s?[a-zA-Z0-9_-]+)', bygroups(Text, Operator.Word, Text, Name.Variable)),
            # (r'\b(if|unless)\b', Operator.Word),
            # # Logical operators
            # (r'(\s+)(lt|gt|or|\|\||!)', bygroups(Text, Operator.Word)),
            #
            # # Numbers
            # # also optional letter supported, like '100s'
            # (r'(\s)([0-9]+)(?=[\t \n])', bygroups(Text, Number)),
            # (r'(\s)([0-9]+)(ms|s|m|h|w|y)', bygroups(Text, Number, Number)),
            # # IP address/subnet
            # # ([\t ]|,)[0-9]+(?:\.[0-9]+){3}(\/[0-9]+)?
            # (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(\/[0-9]+)?', bygroups(Text, Number, Number)),
            # # IP address:port
            #
            # (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(:[0-9]+)?', bygroups(Text, Number, Number)),
            #
            # # Ports only
            # (r'([\.:][0-9]+)', Number),




            # # Path
            # (r'(\s)(\/\S+)', bygroups(Text, String)),
            # # Urls
            # (r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', String),
            # # # Curly Braces
            # # (r'({)(.*?)(})', bygroups(String, Text, String)),
            # # Strings
            # (r'(\".*?\")', bygroups(String.Double)),
            # # Main sections
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist)(\s?)$', bygroups(Name.Namespace, Text)),
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist)(\s?)(.*)$', bygroups(Name.Namespace, Text, Generic.Heading)),
            # # manual fixes (ordering)
            # (r'^([\t ]+)(log-stderr|docroot|index)', bygroups(Text, Keyword.Reserved)),
            # # no option
            # (r'^([\t ]+)(no)(\s+)(option)(\s+)(abortonclose|accept-invalid-http-request|accept-invalid-http-response|allbackups|checkcache|clitcpka|contstats|dontlog-normal|dontlognull|h1-case-adjust-bogus-client|h1-case-adjust-bogus-server|http-buffer-request|http-ignore-probes|http-keep-alive|http-no-delay|http-pretend-keepalive|http-server-close|http-use-proxy-header|httpclose|http_proxy|independent-streams|log-separate-errors|logasap|nolinger|persist|prefer-last-server|redispatch|socket-stats|splice-auto|splice-request|splice-response|srvtcpka|tcp-smart-accept|tcp-smart-connect|transparent)', bygroups(Text, Keyword.Reserved, Text, Keyword.Reserved, Text, Name.Attribute)),
            # # option
            # (r'^([\t ]+)(option)(\s+)(abortonclose|accept-invalid-http-request|accept-invalid-http-response|allbackups|checkcache|clitcpka|contstats|dontlog-normal|dontlognull|forwardfor|h1-case-adjust-bogus-client|h1-case-adjust-bogus-server|http-buffer-request|http-ignore-probes|http-keep-alive|http-no-delay|http-pretend-keepalive|http-server-close|http-use-proxy-header|httpchk|httpclose|httplog|http_proxy|independent-streams|ldap-check|external-check|no\s+log-health-checks|log-health-checks|log-separate-errors|logasap|mysql-check|nolinger|originalto|persist|pgsql-check|smtp-check|prefer-last-server|redispatch|redis-check|smtpchk|socket-stats|splice-auto|splice-request|splice-response|spop-check|srvtcpka|ssl-hello-chk|tcp-check|tcp-smart-accept|tcp-smart-connect|tcpka|tcplog|transparent)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # http-response
            # (r'^([\t ]+)(http-response)(\s+)(add-acl|add-header|allow|cache-store|capture|del-acl|del-header|del-map|deny|redirect|replace-header|replace-value|return|sc-inc-gpc0|sc-inc-gpc1|sc-set-gpt0|send-spoe-group|set-header|set-log-level|set-map|set-mark|set-nice|set-status|set-tos|set-var|silent-drop|strict-mode|track-sc0|track-sc1|track-sc2|unset-var)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # http-request
            # (r'^([\t ]+)(http-request)(\s+)(add-acl|add-header|allow|auth|cache-use|capture|del-acl|del-header|del-map|deny|disable-l7-retry|do-resolve|early-hint|redirect|reject|replace-header|replace-path|replace-uri|replace-value|return|sc-inc-gpc0|sc-inc-gpc1|sc-set-gpt0|set-dst-port|set-dst|set-header|set-log-level|set-map|set-mark|set-method|set-nice|set-path|set-priority-class|set-priority-offset|set-query|set-src-port|set-src|set-tos|set-uri|set-var|send-spoe-group|silent-drop|strict-mode|tarpit|track-sc0|track-sc2|track-sc3|unset-var|use-service|wait-for-handshake)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # tcp-check
            # (r'^([\t ]+)(tcp-check)(\s+)(send-binary|expect|send|comment|connect)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # mailers
            # (r'^([\t ]+)(mailer)(\s+)([a-zA-Z0-9\_\-\.\:]+)', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            # # mailers
            # (r'^([\t ]+)(mailer)', bygroups(Text, Keyword.Reserved)),
            # (r'^([\t ]+)(email-alert)(\s+)(mailers|level|from|to)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # compression
            # (r'^([\t ]+)(compression)(\s+)(algo|offload|type)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # stats
            # (r'^([\t ]+)(stats)(\s+)(admin|auth|enable|hide-version|http-request|realm|refresh|scope|show-desc|show-legends|show-node|uri|socket|bind-process|timeout)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # mode
            # (r'^([\t ]+)(mode)(\s+)(http|tcp|health)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # hold
            # (r'^([\t ]+)(hold)(\s+)(other|refused|nx|timeout|valid|obsolete)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # timeout
            # (r'^([\t ]+)(timeout)(\s+)(check|client-fin|client|connect|http-keep-alive|http-request|queue|server-fin|server|tarpit|tunnel)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # timeout Resolvers
            # (r'^([\t ]+)(timeout)(\s+)(resolve|retry)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # balance
            # (r'^([\t ]+)(balance)(\s+)(roundrobin|static-rr|leastconn|first|source|uri|queue|server-fin|server|tarpit|tunnel)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # # user/group
            # (r'^([\t ]+)(user|group)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, String)),
            # # server
            # (r'^([\t ]+)(server)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            # # use-fcgi-app
            # (r'^([\t ]+)(use-fcgi-app)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            # # default_backend
            # (r'^([\t ]+)(default_backend)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, String)),
            # # use_backend
            # (r'^([\t ]+)(use_backend)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)(\s+)(if)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, Name.Variable, Text, Name.Function, Text, Name.Variable)),
            # (r'^([\t ]+)(use_backend)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)(\s+)', bygroups(Text, Keyword.Reserved, Text, Name.Variable, Text)),
            # # description
            # (r'^([\t ]+)(description)(\s+)(.*$)', bygroups(Text, Keyword.Reserved, Text, String)),
            # # description
            # (r'^([\t ]+)(use_backend)(\s+)([a-z_][a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)', bygroups(Text, Keyword.Reserved, Text, String)),
            # # log
            # (r'^([\t ]+)(log)(\s+)(stdout|stderr|global)', bygroups(Text, Keyword.Reserved, Text, Literal)),
            # (r'^([\t ]+)(default-server)', bygroups(Text, Keyword.Reserved)),
            # # max-mind
            # (r'^([\t ]+)(maxmind-update)(\s+)(url|cache|update|show|status|force-update)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # (r'^([\t ]+)(maxmind-cache-size|maxmind-debug|maxmind-load|maxmind-update)', bygroups(Text, Keyword.Reserved)),
            # # net aquity
            # (r'^([\t ]+)(netacuity-cache-size|netacuity-debug|netacuity-property-separator|netacuity-load|netacuity-update|netacuity-test-ipv4)', bygroups(Text, Keyword.Reserved)),
            # # command
            # (r'^([\t ]+)(command)', bygroups(Text, Keyword.Reserved)),
            # # Global parameters
            # (r'^([\s]+)(master-worker|ca-base|chroot|crt-base|cpu-map|daemon|description|deviceatlas-json-file|deviceatlas-log-level|deviceatlas-separator|deviceatlas-properties-cookie|external-check|gid|group|hard-stop-after|h1-case-adjust|h1-case-adjust-file|localpeer|log-format|log-tag|log-send-hostname|log|lua-load|lua-prepend-path|mworker-max-reloads|nbproc|nbthread|node|pidfile|presetenv|resetenv|uid|ulimit-n|user|set-dumpable|setenv|stats|ssl-default-bind-ciphers|ssl-default-bind-ciphersuites|ssl-default-bind-options|ssl-default-server-ciphers|ssl-default-server-ciphersuites|ssl-default-server-options|ssl-dh-param-file|ssl-server-verify|unix-bind|unsetenv|51degrees-update|51degrees-data-file|51degrees-property-name-list|51degrees-property-separator|51degrees-cache-size|wurfl-update|wurfl-data-file|wurfl-information-list|wurfl-information-list-separator|wurfl-cache-size|strict-limits|busy-polling|max-spread-checks|maxconn|maxconnrate|maxcomprate|maxcompcpuusage|maxpipes|maxsessrate|maxsslconn|maxsslrate|maxzlibmem|noepoll|nokqueue|noevports|nopoll|nosplice|nogetaddrinfo|noreuseport|profiling.tasks|spread-checks|server-state-base|server-state-file|ssl-engine|ssl-mode-async|tune.buffers.limit|tune.buffers.reserve|tune.bufsize|tune.chksize|tune.comp.maxlevel|tune.h2.header-table-size|tune.h2.initial-window-size|tune.h2.max-concurrent-streams|tune.http.cookielen|tune.http.logurilen|tune.http.maxhdr|tune.idletimer|tune.lua.forced-yield|tune.lua.maxmem|tune.lua.session-timeout|tune.lua.task-timeout|tune.lua.service-timeout|tune.maxaccept|tune.maxpollevents|tune.maxrewrite|tune.pattern.cache-size|tune.pipesize|tune.pool-high-fd-ratio|tune.pool-low-fd-ratio|tune.rcvbuf.client|tune.rcvbuf.server|tune.recv_enough|tune.runqueue-depth|tune.sndbuf.client|tune.sndbuf.server|tune.ssl.cachesize|tune.ssl.lifetime|tune.ssl.force-private-cache|tune.ssl.maxrecord|tune.ssl.default-dh-param|tune.ssl.ssl-ctx-cache-size|tune.ssl.capture-cipherlist-size|tune.vars.global-max-size|tune.vars.proc-max-size|tune.vars.reqres-max-size|tune.vars.sess-max-size|tune.vars.txn-max-size|tune.zlib.memlevel|tune.zlib.windowsize|debug|quiet|module-path|module-load|send-metrics-url|send-metrics-header|send-metrics-content-type|send-metrics-data|send-metrics-debug|update)', bygroups( Text, Keyword.Reserved)),
            # (r'^([\t ]+)(acl)(\s+)([a-zA-Z0-9\_\-\.\:]+)', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            # (r'^([\t ]+)(acl|backlog|balance\s+url_param|balance|bind-process|bind|capture\s+cookie|capture\s+response\s+header|capture\s+request\s+header|capture|compression\s+algo|compression\s+type|compression\s+offload|compression|cookie|declare\s+capture|default-server|default_backend|description|disabled|dispatch|dynamic-cookie-key|email-alert\s+from|email-alert\s+level|email-alert\s+mailers|email-alert\s+myhostname|email-alert\s+to|email-alert|enabled|errorfile|errorfiles|errorloc302|errorloc303|errorloc|force-persist|filter|fullconn|grace|hash-balance-factor|hash-type|http-after-response\s+add-header|http-after-response\s+allow|http-after-response\s+del-header|http-after-response\s+replace-header|http-after-response\s+replace-value|http-after-response\s+set-header|http-after-response\s+set-status|http-after-response\s+set-var|http-after-response\s+strict-mode|http-after-response\s+unset-var|http-after-response|http-check\s+disable-on-404|http-check\s+expect|http-check\s+send-state|http-check\s+send|http-check|http-request\s+add-acl|http-request\s+add-header|http-request\s+allow|http-request\s+auth|http-request\s+cache-use|http-request\s+capture|http-request\s+del-acl|http-request\s+del-header|http-request\s+del-map|http-request\s+deny|http-request\s+disable-l7-retry|http-request\s+do-resolve|http-request\s+early-hint|http-request\s+redirect|http-request\s+reject|http-request\s+replace-header|http-request\s+replace-path|http-request\s+replace-uri|http-request\s+replace-value|http-request\s+return|http-request\s+sc-inc-gpc0|http-request\s+sc-inc-gpc1|http-request\s+sc-set-gpt0|http-request\s+set-dst-port|http-request\s+set-dst|http-request\s+set-header|http-request\s+set-log-level|http-request\s+set-map|http-request\s+set-mark|http-request\s+set-method|http-request\s+set-nice|http-request\s+set-path|http-request\s+set-priority-class|http-request\s+set-priority-offset|http-request\s+set-query|http-request\s+set-src-port|http-request\s+set-src|http-request\s+set-tos|http-request\s+set-uri|http-request\s+set-var|http-request\s+send-spoe-group|http-request\s+silent-drop|http-request\s+strict-mode|http-request\s+tarpit|http-request\s+track-sc0|http-request\s+track-sc2|http-request\s+track-sc3|http-request\s+unset-var|http-request\s+use-service|http-request\s+wait-for-handshake|http-request|http-response\s+add-acl|http-response\s+add-header|http-response\s+allow|http-response\s+cache-store|http-response\s+capture|http-response\s+del-acl|http-response\s+del-header|http-response\s+del-map|http-response\s+deny|http-response\s+redirect|http-response\s+replace-header|http-response\s+replace-value|http-response\s+return|http-response\s+sc-inc-gpc0|http-response\s+sc-inc-gpc1|http-response\s+sc-set-gpt0|http-response\s+send-spoe-group|http-response\s+set-header|http-response\s+set-log-level|http-response\s+set-map|http-response\s+set-mark|http-response\s+set-nice|http-response\s+set-status|http-response\s+set-tos|http-response\s+set-var|http-response\s+silent-drop|http-response\s+strict-mode|http-response\s+track-sc0|http-response\s+track-sc1|http-response\s+track-sc2|http-response\s+unset-var|http-response|http-reuse|http-send-name-header|id|ignore-persist|load-server-state-from-file|log-tag|log-format-sd|log-format|log\s+global|no\s+log|max-keep-alive-queue|max-session-srv-conns|maxconn|mode|monitor\s+fail|monitor-net|monitor-uri|no\s+option\s+abortonclose|option\s+abortonclose|no\s+option\s+accept-invalid-http-request|option\s+accept-invalid-http-request|no\s+option\s+accept-invalid-http-response|option\s+accept-invalid-http-response|no\s+option\s+allbackups|option\s+allbackups|no\s+option\s+checkcache|option\s+checkcache|no\s+option\s+clitcpka|option\s+clitcpka|no\s+option\s+contstats|option\s+contstats|no\s+option\s+dontlog-normal|option\s+dontlog-normal|no\s+option\s+dontlognull|option\s+dontlognull|option\s+forwardfor|no\s+option\s+h1-case-adjust-bogus-client|option\s+h1-case-adjust-bogus-client|no\s+option\s+h1-case-adjust-bogus-server|option\s+h1-case-adjust-bogus-server|no\s+option\s+http-buffer-request|option\s+http-buffer-request|no\s+option\s+http-ignore-probes|option\s+http-ignore-probes|no\s+option\s+http-keep-alive|option\s+http-keep-alive|no\s+option\s+http-no-delay|option\s+http-no-delay|no\s+option\s+http-pretend-keepalive|option\s+http-pretend-keepalive|no\s+option\s+http-server-close|option\s+http-server-close|no\s+option\s+http-use-proxy-header|option\s+http-use-proxy-header|option\s+httpchk|no\s+option\s+httpclose|option\s+httpclose|option\s+httplog|no\s+option\s+http_proxy|option\s+http_proxy|no\s+option\s+independent-streams|option\s+independent-streams|option\s+ldap-check|option\s+external-check|no\s+option\s+log-health-checks|option\s+log-health-checks|no\s+option\s+log-separate-errors|option\s+log-separate-errors|no\s+option\s+logasap|option\s+logasap|option\s+mysql-check|no\s+option\s+nolinger|option\s+nolinger|option\s+originalto|no\s+option\s+persist|option\s+persist|option\s+pgsql-check|no\s+option\s+prefer-last-server|option\s+prefer-last-server|no\s+option\s+redispatch|option\s+redispatch|option\s+redis-check|option\s+smtpchk|no\s+option\s+socket-stats|option\s+socket-stats|no\s+option\s+splice-auto|option\s+splice-auto|no\s+option\s+splice-request|option\s+splice-request|no\s+option\s+splice-response|option\s+splice-response|option\s+spop-check|no\s+option\s+srvtcpka|option\s+srvtcpka|option\s+ssl-hello-chk|option\s+tcp-check|no\s+option\s+tcp-smart-accept|option\s+tcp-smart-accept|no\s+option\s+tcp-smart-connect|option\s+tcp-smart-connect|option\s+tcpka|option\s+tcplog|no\s+option\s+transparent|option\s+transparent|no\s+option|option|external-check\s+command|external-check\s+path|external-check|persist\s+rdp-cookie|persist|rate-limit\s+sessions|rate-limit|redirect\s+location|redirect\s+prefix|redirect\s+scheme|redirect|retries|retry-on|server-state-file-name|server-template|server|source|stats\s+admin|stats\s+auth|stats\s+enable|stats\s+hide-version|stats\s+http-request|stats\s+realm|stats\s+refresh|stats\s+scope|stats\s+show-desc|stats\s+show-legends|stats\s+show-node|stats\s+uri|stats|stick\s+match|stick\s+on|stick\s+store-request|stick\s+store-response|stick|stick-table\s+type|stick-table|tcp-check\s+connect|tcp-check\s+expect|tcp-check\s+send|tcp-check\s+send-binary|tcp-check|tcp-request\s+connection|tcp-request\s+content|tcp-request\s+inspect-delay|tcp-request\s+session|tcp-request|tcp-response\s+content|tcp-response\s+inspect-delay|tcp-response|timeout\s+check|timeout\s+client|timeout\s+client-fin|timeout\s+connect|timeout\s+http-keep-alive|timeout\s+http-request|timeout\s+queue|timeout\s+server|timeout\s+server-fin|timeout\s+tarpit|timeout\s+tunnel|timeout|transparent|unique-id-format|unique-id-header|use_backend|use-fcgi-app|use-server|path-info|table)', bygroups(Text, Keyword.Reserved)),
            # # cache
            # (r'^([\t ]+)(total-max-size|max-age)', bygroups(Text, Keyword.Reserved)),
            # # resolvers
            # (r'^([\t ]+)(parse-resolv-conf|resolve_retries|nameserver|accepted_payload_size)', bygroups(Text, Keyword.Reserved)),
            # # functions
            # (r'(\s)(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(\S+)(\s+)(})', bygroups(Text, Name.Function, Text, String, Text, Text)),
            # (r'(\s)(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(.+)$', bygroups(Text, Name.Function, Text, String)),
            # (r'(\s)(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)', bygroups(Text, Name.Function)),
            # (r'(\s)(addr)', bygroups(Text, Name.Function)),
            # (r'(\s)(verify|none|crt|tfo|check-ssl|check|alpn)', bygroups(Text, Name.Function)),
            # (r'(\s)(accept-netscaler-cip|accept-proxy|allow-0rtt|alpn|backlog|ca-file|ca-ignore-err|ca-sign-file|ca-sign-pass|ciphers|ciphersuites|crl-file|crt|crt-ignore-err|crt-list|curves|defer-accept|ecdhe|expose-fd listeners|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|generate-certificates|gid|group|id|interface|level|maxconn|mode|mss|namespace|name|nice|no-ca-names|no-sslv3|no-tls-tickets|no-tlsv10|no-tlsv11|no-tlsv12|no-tlsv13|npn|prefer-client-ciphers|process|proto|severity-output|ssl-max-ver|ssl-min-ver|ssl_fc|ssl|strict-sni|tcp-ut|tfo|tls-ticket-keys|transparent|uid|user|v4v6|v6only|verify)', bygroups(Text, Name.Function)),
            # (r'(\s)(location|scheme|prefix|random)', bygroups(Text, Name.Function)),
            # (r'(\s)(type|string|size|store|http_req_rate|http_req_cnt)', bygroups(Text, Name.Function)),
            # (r'(\s)(SSLv3|TLSv1.0|TLSv1.1|TLSv1.2|TLSv1.3)', bygroups(Text, Literal)),
            # (r'(\s)(conn-failure|empty-response|junk-response|response-timeout|0rtt-rejected|except|nbsrv)', bygroups(Text, Name.Function)),
            # # ACL conditionals
            # (r'\b(if|unless)\b', Name.Function),
            # # Logical operators
            # (r'\s+(or|\|\||!)\s+', Operator.Word),
            # # Comment
            # (r'#.*$', Comment.Singleline),
            # # Numbers
            # # also optional letter supported, like '100s'
            # (r'(\s)([0-9]+)([\s?])', bygroups(Text, Number, Text)),
            # (r'(\s)([0-9]+)([a-z])', bygroups(Text, Number, Number)),
            # # IP address/subnet
            # (r'\s[0-9]+(?:\.[0-9]+){3}(/[0-9]+)?', Number),
            # # IP address:port
            # (r'\s[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?', Number),
            # # Ports only
            # (r'([\.:][0-9]+)', Number),
            # (r'.', Text)
        ]
    }
