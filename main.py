#!/usr/bin/env python

import re
import ipaddress
import json
import gzip
from tqdm import tqdm

print_rows = False

class RouterSessionDump():
    """Representation of a recorded router session

    This session may contain tables that can be parsed by
    CiscoTableParser subclasses.
    """

    def __init__(self, filename):
        if re.match(r"^.*\.gz$", filename):
            with gzip.open(filename, 'rt', encoding='UTF-8') as file:
                self.lines = file.readlines()
        else:
            with open(filename) as file:
                self.lines = file.readlines()

    def call_parser(self, parser):
        return parser.parse_lines(self.lines)


class ParseError(Exception):
    pass


class ParseErrorHeaderNotFound(ParseError):
    def __init__(self):
        super().__init__("Parse Error: Table header not found")


class CiscoTableParser():
    """Generic parser for Cisco CLI tabular output

    This is supposed to be subclassed for specific tables.
    """
    fields = []

    def init_row(self):
        self.row = []

    def process_field(self, field, value):
        self.row.append(value)

    def finish_row(self):
        return self.row

    def init_table(self):
        self.table = []

    def process_row(self, row):
        self.table.append(row)

    def finish_table(self):
        return self.table

    def __init__(self):
        self.header_regexp = re.compile(self.collect_field_header_regexps())

    def collect_field_header_regexps(self):
        re = r'^'
        for field in self.fields:
            if isinstance(field['parser'], CiscoSingleCharFieldParser):
                re += r' '
            else:
                re += r'('+field['parser'].header_subregexp()+r')'
        return re+r'$'

    def parse_row(self, lines, start, end):
        """Parse a single table row

        Parse a table row from LINES, starting at line number START,
        limited by line number END.

        Results if successful:
        * a row entry (as built by finish_row())
        * the number of the line after the parsed row

        Otherwise, throw an error.
        """
        self.init_row()
        i = start
        # Parse actual contents of the table
        col = 0
        line = lines[i].expandtabs()
        if line[-1] == '\n':
            line = line[:-1]
        for field_no in range(0, len(self.fields)):
            field = self.fields[field_no]
            parser = field['parser']
            if isinstance(parser, CiscoSingleCharFieldParser):
                parsed_field, width = parser.parse(line, col, len(line))
                self.process_field(field, parsed_field)
                col += 1
            else:
                if len(line) < col:
                    i += 1
                    line = lines[i].expandtabs()
                parsed_field, width = parser.parse(line, col, len(line))
                self.process_field(field, parsed_field)
                if parsed_field is None:
                    if 'width' in field:
                        raise ParseError(f"Cannot parse field {field} in [{line[col:col+field['width']]}]")
                    else:
                        raise ParseError(f"Cannot parse field {field} in [{line[col:]}]")
                if 'width' in field:
                    prev_col = col
                    col += field['width']
                    if prev_col + width >= col:
                        i += 1
                        line = lines[i].expandtabs()
                        ##
                        ## This is due to a bug in Cisco's BGP table
                        ## output that can be seen in this example output
                        ##
                        ## V* i2001:620:0:ff::2/128
                        ##                       2001:620:0:c000::29
                        ##                                                0    100      0 65501 ?
                        ## V* i                   2001:620:0:c000::2
                        ##
                        ## The "NextHop" field in the continuation line
                        ## starts one column early.
                        ##
                        ## Our workaround is to shift the cursor left
                        ## until our column position is preceded by a
                        ## space.
                        ##
                        while col > len(line) or line[col-1] != ' ':
                            col -= 1
                        ##
                        ## Unfortunately, it turns out that this is not sufficient.
                        ## Sometimes the indentation error happens with a field
                        ## that is right-aligned, to the "preceded by a space"
                        ## test sometimes gives false positives.
                        ##
                    ##
                    ## Therefore, we need to apply this workaround
                    ## on subsequent fields as well.
                    ##
                    if field_no > 0:
                        if col < len(line) and line[col-1] != ' ':
                            if line[col-1] != ' ':
                                col -= 1
                                if line[col-1] != ' ':
                                    col -= 1
                                    if line[col-1] != ' ':
                                        raise ParseError(f"line {line}\n{' ' * col}^\nfield {field}")

        i += 1
        return self.finish_row(), i

    def find_table(self, lines, start, end):
        """Locate table in LINES between START and END.

        If one is found, compute the index of each column based on the
        table header, and return:

        * the number of the first line of data (followingn the header)
        * the number of the first line after the end of the table

        If no table is found, return False and END.
        """
        table_body_start, table_end = None, None
        i = start
        if not end:
            end = len(lines)
        while True:
            if i >= end:
                return False, i
            m = re.match(self.header_regexp, lines[i].expandtabs())
            if m:
                table_body_start = i+1
                break
            i += 1
        column = 0
        field_count = 0
        group_count = 1
        for field in self.fields:
            if isinstance(field['parser'], CiscoSingleCharFieldParser):
                field['width'] = 1
                column += field['width']
            else:
                if field != self.fields[-1]:
                    field['width'] = len(m.group(group_count))
                    group_count += 1
                    column += field['width']
        i += 1
        while i < end:
            if lines[i] == "\n":
                table_end = i+1
                break
            i += 1
        if not table_end:
            table_end = end
        return table_body_start, table_end

    def parse_table(self, lines, start, end):
        """Parse an entire table

        Try to find the first table in LINES starting at line number START
        and limited by line number END.

        If no table is found, return None and END.

        If a table is found and successfully parsed, return
        * a representation of the table as produced by self.finish_table()
        * the number of the first line after the end of the table.
        """

        self.init_table()

        table_body_start, table_end = self.find_table(lines, start, end)
        if not table_body_start:
            return None, end

        next_line = table_body_start
        result = None

        for i in tqdm(range(table_body_start, table_end), unit='lines'):
            if i < next_line:
                continue
            if i >= table_end or lines[i] == "\n":
                return self.finish_table(), table_end
            result, next_line = self.parse_row(lines, i, end)
            if not result:
                raise ParseError()
            self.process_row(result)
            if print_rows:
                print(f"row: {result}")
        return None

    def parse_lines(self, lines, start=0, end=None):
        self.tables = []
        cursor = start
        while True:
            table, cursor = self.parse_table(lines, cursor, end)
            if not table:
                return self.tables
            else:
                self.tables.append(table)


class CiscoFieldParser():
    def parse(self, line, start, end):
        if len(line) < start:
            return False, 0
        return self.parse_field(line[start:])


class CiscoSingleCharFieldParser(CiscoFieldParser):
    def header_subregexp(self):
        return ' '

    def parse(self, line, start, end):
        if len(line) <= start:
            return False, 0
        return self.parse_field(line[start:start+1])


class BgpStatusValidityParser(CiscoSingleCharFieldParser):
    def parse_field(self, field):
        m = re.match(r'([sdh* ])', field)
        if m:
            return m.group(1), 1
        else:
            return False, 0


class BgpAspaStatusParser(CiscoSingleCharFieldParser):
    def parse_field(self, field):
        m = re.match(r'([UVI])', field)
        if m:
            return m.group(1), 1
        else:
            return False, 0


class BgpStatusBestParser(CiscoSingleCharFieldParser):
    def parse_field(self, field):
        m = re.match(r'([ >])', field)
        if m:
            return m.group(1), 1
        else:
            return False, 0


class BgpStatusNextHopParser(CiscoSingleCharFieldParser):
    def parse_field(self, field):
        m = re.match(r'([irSN])', field)
        if m:
            return m.group(1), len(m.group(0))
        else:
            return False, 0


class BgpNetworkParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Network\s+'

    def parse_field(self, field):
        m = re.match(r'^(\S+)', field)
        if not m:
            return False, 0
        field = m.group(1)
        return ipaddress.ip_network(field), len(m.group(0))


class BgpNextHopParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Next Hop\s+'

    def parse_field(self, field):
        m = re.match(r'^(\S+)', field)
        if not m:
            return False, 0
        field = m.group(1)
        return ipaddress.ip_address(field), len(m.group(0))


class BgpMetricParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Metric\s+'

    def parse_field(self, field):
        m = re.match(r'^(\d*)', field)
        if not m:
            return False, 0
        field = m.group(1)
        if len(field) == 0:
            return False, 0
        return int(field), len(m.group(0))


class BgpLocPrfParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'LocPrf\s+'

    def parse_field(self, field):
        m = re.match(r'^\s*(\d+)', field)
        if not m:
            return False, 0
        field = m.group(1)
        return int(field), len(m.group(0))


class BgpWeightParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Weight\s+'

    def parse_field(self, field):
        m = re.match(r'^\s*(\d+)', field)
        if not m:
            return False, 0
        field = m.group(1)
        return int(field), len(m.group(0))


class BgpPathParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Path'

    def parse_field(self, field):
        m = re.match(r'^(([{,}0-9 ]+)+[ei?])', field)
        if not m:
            return False, 0
        field = m.group(1)
        return field, len(m.group(0))

BASIC_BGP_TABLE_FIELDS = [
        {"parser": BgpStatusValidityParser()},
        {"parser": BgpStatusBestParser()},
        {"parser": BgpStatusNextHopParser()},
        {"parser": BgpNetworkParser()},
        {"parser": BgpNextHopParser()},
        {"parser": BgpMetricParser()},
        {"parser": BgpLocPrfParser()},
        {"parser": BgpWeightParser()},
        {"parser": BgpPathParser()},
]


class CiscoBgpTableParser(CiscoTableParser):
    fields = BASIC_BGP_TABLE_FIELDS

    def init_row(self):
        self.row = []

    def process_field(self, field, value):
        self.row.append(value)

    def field_index(self, parser_type):
        for field_no in range(0, len(self.fields)):
            field = self.fields[field_no]
            if isinstance(field['parser'], BgpNetworkParser):
                return field_no
        return None

    def finish_row(self):
        prefix_index = self.field_index(BgpNetworkParser)
        prefix = self.row[prefix_index]
        if prefix:
            self.current_prefix = prefix
        else:
            self.row[prefix_index] = self.current_prefix
        return self.row

    def init_table(self):
        self.paths_by_prefix = dict()

    def process_row(self, row):
        self.paths_by_prefix.setdefault(self.current_prefix, []).append(self.row)

    def finish_table(self):
        return self.paths_by_prefix

    def __init__(self):
        super().__init__()
        self.current_prefix = None


class CiscoAspaValidityTableParser(CiscoBgpTableParser):
    fields = [
        {"parser": BgpAspaStatusParser()}
    ] + BASIC_BGP_TABLE_FIELDS


class BgpAspaCustomerAsParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'  Customer AS\s+'

    def parse_field(self, field):
        m = re.match(r'^\s*(\d+)', field)
        if not m:
            return False, 0
        field = m.group(1)
        return int(field), len(m.group(0))


class BgpAspaProviderAsParser(CiscoFieldParser):
    def header_subregexp(self):
        return r'Provider AS'

    def parse_field(self, field):
        m = re.match(r'^\s*((\d+)(\s+\d+)*)\s*$', field)
        if not m:
            return False, 0
        field = [int(x) for x in m.group(1).split()]
        return field, len(m.group(0))



class CiscoRpkiAspaTableParser(CiscoTableParser):
    fields = [
        {"parser": BgpAspaCustomerAsParser()},
        {"parser": BgpAspaProviderAsParser()}
    ]

def remove_prefixes_without_invalid_paths(paths_by_prefix):
    result = dict()
    for k, v in paths_by_prefix.items():
        if any([path[0] == 'I' for path in v]):
            result[k] = v
    return result


def collect_by_path(table, by_path=dict()):
    for prefix, paths in table.items():
        for path in paths:
            as_path = path[9]
            by_path.setdefault(as_path, []).append(path)
    return by_path


class RpkiCache():
    def __init__(self, filename_or_dump, own_as=559, ignore_roas=True, ignore_aspas=False):
        self.own_as = own_as
        self.roas = self.aspas = None
        if isinstance(filename_or_dump, str):
            self.init_from_filename(filename_or_dump, own_as=own_as, ignore_roas=ignore_roas, ignore_aspas=ignore_aspas)
        elif isinstance(filename_or_dump, RouterSessionDump):
            self.init_from_router_session_dump(filename_or_dump, own_as=own_as, ignore_roas=ignore_roas, ignore_aspas=ignore_aspas)
        else:
            raise Error(f"Don\'t know how to initialize RPKI cache from {filename_or_dump}")

    def init_from_filename(self, filename, own_as, ignore_roas=True, ignore_aspas=False):
        if re.match(r"^.*\.gz$", filename):
            with gzip.open(filename, 'rt', encoding='UTF-8') as file:
                self.load_rpki_cache_from_file(file, filename, own_as=own_as, ignore_roas=ignore_roas, ignore_aspas=ignore_aspas)
        else:
            with open(filename) as file:
                self.load_rpki_cache_from_file(file, filename, own_as=own_as, ignore_roas=ignore_roas, ignore_aspas=ignore_aspas)

    def init_from_router_session_dump(self, dump: RouterSessionDump, own_as=559, ignore_roas=True, ignore_aspas=False):
        self.aspas = dict()
        if not ignore_aspas:
            a_parser = CiscoRpkiAspaTableParser()
            aspas = dump.call_parser(a_parser)
            for aspa in aspas[0]: # weird shape
                if not aspa[0]:   # and sometimes the aspa looks like [None, None]
                    continue
                customer_asid = aspa[0]
                for provider in aspa[1]:
                    self.aspas.setdefault(customer_asid, set()).add(provider)
        if not ignore_roas:
            raise NotImplementedError(f"Cannot parse ROAs from router session dump")


    def load_rpki_cache_from_file(self, file, filename, own_as, ignore_roas, ignore_aspas):
        content = json.load(file)
        if not ignore_roas:
            self.roas = content['roas']
        if not ignore_aspas:
            self.aspas = dict()
            for aspa in content['aspas']:
                customer_asid = aspa['customer_asid']
                providers = aspa['providers']
                for provider in providers:
                    self.aspas.setdefault(customer_asid, set()).add(provider)

    def __str__(self):
        result = f"#<{type(self).__name__}"
        if self.roas:
            result += f", {len(self.roas)} ROAs"
        if self.aspas:
            result += f", {len(self.aspas)} ASPAs"
        result += ">"
        return result


def as_relation(as1, as2, rpki_cache):
    """Return the relationship between AS1 and AS2 as per ASPAs

    The result is string that starts and ends with a space.

    If neither AS has an ASPA, AS1 AS2, i.e. the string consists of a single space.
    If AS1 has an ASPA that contains AS2, AS1 ⇒ AS2 (unless AS2 also has an ASPA).
    If AS1 has an ASPA that doesn't contain AS2, AS1 ⇏ AS2 (unless AS2 also has an ASPA).
    If AS2 has an ASPA that contains AS1, AS1 ⇐ AS2 (unless AS1 also has an ASPA).
    If AS2 has an ASPA that doesn't contain AS1, AS1 ⇍ AS2 (unless AS1 also has an ASPA).
    The remaining cases are when both ASes have ASPAs:
      If AS1 and AS2 include each other in their ASPAs, AS1 ⇔ AS2.
      If neither AS1 nor AS2 include each other in their ASPAs, AS1 ⇍ AS2.
      If AS1 includes AS2 in their ASPA, but AS2's doesn't include AS1: AS1 ⇒⇍ AS2.
      If AS2 includes AS1 in their ASPA, but AS1's doesn't include AS2: AS1 ⇏⇐ AS2.
    """
    if as1 == as2:
        return " "

    def as_rel(as1, as2, rpki_cache):
        aspa = rpki_cache.aspas.get(as1)
        return 0 if not aspa else 1 if as2 in aspa else 2
    as1_2 = as_rel(as1, as2, rpki_cache)
    as2_1 = as_rel(as2, as1, rpki_cache)
    return [[" ",   " ⇒ ",  " ⇏ "],
            [" ⇐ ", " ⇔ ",  " ⇏⇐ "],
            [" ⇍ ", " ⇒⇍ ", " ⇎ "]][as2_1][as1_2]


def print_path_with_aspas(path, rpki_cache):
    m = re.match(r"^(.*) ([ie?])$", path)
    if not m:
        raise Error(f"Cannot parse AS path {path}")
    ases = [int(x) for x in m.group(1).split()]
    ases = [rpki_cache.own_as] + ases
    origin_code = m.group(2)
    if len(ases) > 0:
        print(f"AS{ases[0]}", end='')
        for index in range(1, len(ases)):
            print(f"{as_relation(ases[index-1], ases[index], rpki_cache)}AS{ases[index]}", end='')
    print(f" {origin_code}")

ASPA_UNKNOWN = 0
ASPA_VALID = 1
ASPA_INVALID = 2

def pretty_aspa_result(x):
    if x == ASPA_UNKNOWN:
        return "?"
    if x == ASPA_VALID:
        return "V"
    if x == ASPA_INVALID:
        return "I"
    raise NotImplementedError(f"Unsupported ASPA result value {x}")

def check_aspa(as_path, rpki_cache):
    # 1. Check for AS Sets
    for item in as_path:
        if isinstance(item, list):
            return ASPA_INVALID

    # 2. Compress AS Path (remove adjacent duplicates)
    compressed_path = []
    if as_path:
        compressed_path.append(as_path[0])
        for i in range(1, len(as_path)):
            if as_path[i] != as_path[i-1]:
                compressed_path.append(as_path[i])

    N = len(compressed_path)
    if N == 0:
        return ASPA_INVALID

    # 3. Determine Algorithm (Upstream vs Downstream)
    # Heuristic: If neighbor (AS(N)) is in own_as's providers => Downstream (received from provider).
    # Else => Upstream.
    neighbor_as = compressed_path[0]
    own_providers = rpki_cache.aspas.get(rpki_cache.own_as) if rpki_cache.aspas else None

    is_downstream = False
    if own_providers and neighbor_as in own_providers:
        is_downstream = True

    # Helper for provider authorization
    # Returns: 0 (No Attestation), 1 (Provider+), 2 (Not Provider+)
    AUTH_NO_ATTESTATION = 0
    AUTH_PROVIDER_PLUS = 1
    AUTH_NOT_PROVIDER_PLUS = 2

    def authorized(as_x, as_y):
        if not rpki_cache.aspas:
            return AUTH_NO_ATTESTATION
        providers = rpki_cache.aspas.get(as_x)
        if providers is None:
            return AUTH_NO_ATTESTATION
        if as_y in providers:
            return AUTH_PROVIDER_PLUS
        return AUTH_NOT_PROVIDER_PLUS

    # Map indices: AS(k) corresponds to compressed_path[N-k]
    # AS(1) is compressed_path[N-1] (last element)
    # AS(N) is compressed_path[0] (first element)

    def get_as(k):
        # k is 1-based index from Origin
        return compressed_path[N-k]

    # 4. Calculate max_up_ramp
    # I ranges from 1 upwards.
    # Check authorized(A(I), A(I+1))
    max_up_ramp = N
    for I in range(1, N):
        u = get_as(I)
        v = get_as(I+1)
        auth = authorized(u, v)
        if auth == AUTH_NOT_PROVIDER_PLUS:
            max_up_ramp = I
            break

    # 5. Calculate min_up_ramp
    min_up_ramp = N
    for I in range(1, N):
        u = get_as(I)
        v = get_as(I+1)
        auth = authorized(u, v)
        if auth in (AUTH_NO_ATTESTATION, AUTH_NOT_PROVIDER_PLUS):
            min_up_ramp = I
            break

    # 6. Calculate max_down_ramp, min_down_ramp
    max_down_ramp = 0
    min_down_ramp = 0

    if is_downstream:
        # Down-ramp logic
        # Iterate J from N down to 2.
        # Check authorized(A(J), A(J-1))

        # Calculate max_down_ramp
        max_down_ramp = N # Default if no break
        for J in range(N, 1, -1):
            u = get_as(J)
            v = get_as(J-1)
            auth = authorized(u, v)
            if auth == AUTH_NOT_PROVIDER_PLUS:
                max_down_ramp = N - J + 1
                break

        # Calculate min_down_ramp
        min_down_ramp = N # Default if no break
        for J in range(N, 1, -1):
            u = get_as(J)
            v = get_as(J-1)
            auth = authorized(u, v)
            if auth in (AUTH_NO_ATTESTATION, AUTH_NOT_PROVIDER_PLUS):
                min_down_ramp = N - J + 1
                break
    else:
        # Upstream: max_down_ramp = min_down_ramp = 0 (already set)
        pass

    # 7. Apply Checks
    if is_downstream:
        # Downstream check
        if max_up_ramp + max_down_ramp - 1 < N:
            return ASPA_INVALID
        if min_up_ramp + min_down_ramp - 1 < N:
            return ASPA_UNKNOWN
        return ASPA_VALID
    else:
        # Upstream check
        if max_up_ramp < N:
            return ASPA_INVALID
        if min_up_ramp < N:
            return ASPA_UNKNOWN
        return ASPA_VALID


def print_invalid_paths(by_path, rpki_cache, print_prefixes):
    as_set_paths = []
    he_paths = []
    sorted_paths = list(by_path.keys())
    sorted_paths.sort()
    for path in sorted_paths:
        prefixes_etc = by_path[path]
        if re.match(r".*{.*}", path):
            as_set_paths.append(path)
        elif re.match(r"^6939 .*", path):
            he_paths.append(path)
        else:
            clean_path = [int(x) for x in path.split(' ')[:-1]]
            print_path_with_aspas(path, rpki_cache)
            check = check_aspa(clean_path, rpki_cache)
            if check != ASPA_INVALID:
                print(f"Wait... check_aspa returned {pretty_aspa_result(check)}")
            if print_prefixes:
                for prefix_etc in sorted(prefixes_etc, key=lambda x: [x[4].version, x[4]]):
                    prefix = prefix_etc[4]
                    print (f"  {prefix_etc}")
    if as_set_paths:
        print(f"Found {len(as_set_paths)} AS paths invalid due to AS-Sets:\n{as_set_paths}")
    if he_paths:
        print(f"Found {len(he_paths)} AS paths invalid due to Hurricane Electric (AS6939)\n{he_paths}")


def main():
    test_all = False
    test_individual_aspa_parsers = False
    test_aspa_parsers = True
    print_prefixes = False

    if test_all:
        parse_file("aspa.20260126-1658.gz")
    elif test_individual_aspa_parsers:
        parser = CiscoBgpTableParser()
        parser.parse_file("bgp-aspa-invalid-ipv4.txt")
        parser.parse_file("bgp-aspa-invalid-ipv6.txt")
    elif test_aspa_parsers:
        dump = RouterSessionDump("aspa.20260202-2058.gz")
        #dump = RouterSessionDump("small-sample.txt")
        #dump = RouterSessionDump("aspa-table-only-sample.txt")
        rpki_cache = RpkiCache(dump)
        v_parser = CiscoAspaValidityTableParser()
        tables = dump.call_parser(v_parser)
        by_path = dict()
        for table in tables:
            table = remove_prefixes_without_invalid_paths(table)
            by_path = collect_by_path(table, by_path)
            print_invalid_paths(by_path, rpki_cache=rpki_cache, print_prefixes=print_prefixes)


if __name__ == "__main__":
    main()
