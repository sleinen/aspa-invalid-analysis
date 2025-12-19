#!/usr/bin/env python

import re
import ipaddress
import json

print_rows = False

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
        self.init_row()
        i = start
        # Parse actual contents of the table
        col = 0
        line = lines[i]
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
                    line = lines[i]
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
                        line = lines[i]
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
                        while line[col-1] != ' ':
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

    def parse_table(self, lines, start, end):
        self.init_table()
        i = start
        if not end:
            end = len(lines)
        while True:
            if i >= end:
                return False, i
            m = re.match(self.header_regexp, lines[i])
            if m:
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
            if i % 10000 == 0:
                print(f"line {i}")
            if lines[i] == "\n":
                return self.finish_table(), i+1
            result, next_line = self.parse_row(lines, i, end)
            if not result:
                raise ParseError()
            self.process_row(result)
            if print_rows:
                print(f"row: {result}")
            i = next_line
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

    def parse_file(self, filename):
        with open(filename) as file:
            return self.parse_lines(file.readlines())


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


class CiscoAspaTableParser(CiscoBgpTableParser):
    fields = [
        {"parser": BgpAspaStatusParser()}
    ] + BASIC_BGP_TABLE_FIELDS


def remove_prefixes_without_invalid_paths(paths_by_prefix):
    result = dict()
    for k, v in paths_by_prefix.items():
        if any([path[0] == 'I' for path in v]):
            result[k] = v
    return result


def collect_by_path(table):
    result = dict()
    for prefix, paths in table.items():
        for path in paths:
            as_path = path[9]
            result.setdefault(as_path, []).append(path)
    return result


class RpkiCache():
    def __init__(self, filename, ignore_roas=True, ignore_aspas=False):
        self.roas = self.aspas = None
        with open(filename) as file:
            content = json.load(file)
            if not ignore_roas:
                self.roas = content['roas']
            if not ignore_aspas:
                self.aspas = content['aspas']

    def __str__(self):
        result = f"#<{type(self).__name__}"
        if self.roas:
            result += f", {len(self.roas)} ROAs"
        if self.aspas:
            result += f", {len(self.aspas)} ASPAs"
        result += ">"
        return result


def print_invalid_paths(by_path, rpki_cache, print_prefixes):
    as_set_paths = []
    he_paths = []
    sorted_paths = list(by_path.keys())
    sorted_paths.sort()
    for path in sorted_paths:
        prefixes = by_path[path]
        if re.match(r".*{.*}", path):
            as_set_paths.append(path)
        elif re.match(r"^6939 .*", path):
            he_paths.append(path)
        else:
            print (f"{path}")
            if print_prefixes:
                for prefix in prefixes.sorted():
                    print (f"  {prefix}")
    if as_set_paths:
        print(f"Found {len(as_set_paths)} AS paths invalid due to AS-Sets:\n{as_set_paths}")
    if he_paths:
        print(f"Found {len(he_paths)} AS paths invalid due to Hurricane Electric (AS6939)\n{he_paths}")


def main():
    test_all = False
    test_individual_aspa_parsers = False
    test_aspa_parsers = True
    print_prefixes = False

    rpki_cache = RpkiCache("rpki.json")
    print(rpki_cache)

    if test_all:
        parse_file("sample-input.0.txt")
    elif test_individual_aspa_parsers:
        parser = CiscoBgpTableParser()
        parser.parse_file("bgp-aspa-invalid-ipv4.txt")
        parser.parse_file("bgp-aspa-invalid-ipv6.txt")
    elif test_aspa_parsers:
        parser = CiscoAspaTableParser()
        tables = parser.parse_file("20251215-aspa-validity.txt")
        for table in tables:
            table = remove_prefixes_without_invalid_paths(table)
            by_path = collect_by_path(table)
            print_invalid_paths(by_path, rpki_cache=rpki_cache, print_prefixes=print_prefixes)


if __name__ == "__main__":
    main()
