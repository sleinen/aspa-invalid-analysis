#!/usr/bin/env python

import re
import ipaddress


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

    def __init__(self):
        self.header_regexp = re.compile(self.collect_field_header_regexps())
        print(f"REGEXP: {self.header_regexp}")

    def collect_field_header_regexps(self):
        re = r'^'
        for field in self.fields:
            if isinstance(field['parser'], CiscoSingleCharFieldParser):
                re += r' '
            else:
                re += r'('+field['parser'].header_subregexp()+r')'
        return re+r'$'

    def parse_row(self, lines, start, end):
        result = []
        i = start
        # Parse actual contents of the table
        col = 0
        line = lines[i]
        if line[-1] == '\n':
            line = line[:-1]
        for field_no in range(0, len(self.fields)):
            field = self.fields[field_no]
            #print(f"at line {i}, field {field}")
            parser = field['parser']
            if isinstance(parser, CiscoSingleCharFieldParser):
                parsed_field, width = parser.parse(line, col, len(line))
                result.append(parsed_field)
                col += 1
            else:
                if len(line) < col:
                    i += 1
                    line = lines[i]
                parsed_field, width = parser.parse(line, col, len(line))
                result.append(parsed_field)
                if parsed_field is None:
                    if 'width' in field:
                        raise ParseError(f"Cannot parse field {field} in [{line[col:col+field['width']]}]")
                    else:
                        raise ParseError(f"Cannot parse field {field} in [{line[col:]}]")
                else:
                    result.append(parsed_field)
                if 'width' in field:
                    prev_col = col
                    col += field['width']
                    if prev_col + width >= col:
                        i += 1
                        line = lines[i]
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
        i += 1
        return result, i

    def parse_table(self, lines, start, end):
        self.table = []
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
        print(f"match: {m}, group_count: {len(m.groups())} after ignoring {i-start} lines")
        column = 0
        field_count = 0
        group_count = 1
        for field in self.fields:
            print(f"column {column} field {field}")
            if isinstance(field['parser'], CiscoSingleCharFieldParser):
                field['width'] = 1
                column += field['width']
            else:
                print (f"[{m.group(group_count)}]")
                if field != self.fields[-1]:
                    field['width'] = len(m.group(group_count))
                    group_count += 1
                    column += field['width']
        i += 1
        try:
            while i < end:
                if i % 10000 == 0:
                    print(f"line {i}")
                if lines[i] == "\n":
                    return self.table, i+1
                result, next_line = self.parse_row(lines, i, end)
                if not result:
                    raise ParseError()
                self.table.append(result)
                if print_rows:
                    print(f"row: {result}")
                i = next_line
        except Exception as c:
            print(f"Exception: {c}, line {i}: {lines[i]}")
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

class CiscoAspaTableParser(CiscoBgpTableParser):
    fields = [
        {"parser": BgpAspaStatusParser()}
    ] + BASIC_BGP_TABLE_FIELDS

re_TITLE = re.compile(r'(   )(Network\s+)(Next Hop\s+)(Metric\s+)(LocPrf\s+)(Weight\s+)(Path)')

re_PREFIX_WITH_PATH = re.compile(r'^[\* ][> ](\S+)\s+(\S+)\s+((\d+)\s+)?')
re_PREFIX_NEXTHOP_ONLY = re.compile(r'^[\* ][> ](\S+)\s+(\S+)')
re_PATH_ONLY = re.compile(r'^[\* ][> ](\S+)\s+(\S+)\s+((\d+)\s+)?')
re_PATH_CONTINUATION = re.compile(r'^                                         \s*((\d+)\s+)?')


def main():
    test_all = False
    test_individual_aspa_parsers = False
    test_aspa_parsers = True

    if test_all:
        parse_file("sample-input.0.txt")
    elif test_individual_aspa_parsers:
        parser = CiscoBgpTableParser()
        parser.parse_file("bgp-aspa-invalid-ipv4.txt")
        parser.parse_file("bgp-aspa-invalid-ipv6.txt")
    elif test_aspa_parsers:
        parser = CiscoAspaTableParser()
        tables = parser.parse_file("20251215-aspa-validity.txt")
        print(f"{tables}")

if __name__ == "__main__":
    main()
