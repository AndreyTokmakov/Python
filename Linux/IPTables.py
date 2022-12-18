import subprocess
from typing import List, Dict, Tuple


class TestData:
    test_input: List = '''Chain PREROUTING (policy ACCEPT 219K packets, 11M bytes)
num   pkts bytes target     prot opt in     out     source               destination         
        
Chain INPUT (policy ACCEPT 197K packets, 9097K bytes)
num   pkts bytes target     prot opt in     out     source               destination         
        
Chain OUTPUT (policy ACCEPT 4228 packets, 437K bytes)
num   pkts bytes target     prot opt in     out     source               destination         

Chain POSTROUTING (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1     5850  736K MASQUERADE  all  --  *      eth0    0.0.0.0/0            0.0.0.0/0
'''.split('\n')


class Utilities(object):

    @staticmethod
    def ExecuteCommand(cmd: List) -> List[str]:
        try:
            proc = subprocess.Popen(cmd, text=True, shell=False,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            output: List = []
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                output.append(line.rstrip())

        except OSError as exc:
            raise exc

        proc.wait()
        return output


class Chain(object):

    def __init__(self,
                 name: str = "",
                 policy: str = ""):
        self.__name: str = name
        self.__policy: str = policy
        self.__packets: int = 0
        self.__bytes: int = 0

        self.rules = []

    @property
    def name(self) -> str:
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def policy(self) -> str:
        return self.__policy

    @policy.setter
    def policy(self, value):
        self.__policy = value

    @property
    def packets(self) -> int:
        return self.__packets

    @packets.setter
    def packets(self, value):
        self.__packets = value

    @property
    def bytes(self) -> int:
        return self.__bytes

    @bytes.setter
    def bytes(self, value):
        self.__bytes = value

    def __repr__(self):
        return f'{self.name} [policy: {self.__policy}, packets: {self.__packets}, bytes: {self.__bytes}]'

    def __str__(self):
        return f'{self.name} [policy: {self.__policy}, packets: {self.__packets}, bytes: {self.__bytes}]'


class IPTables(object):

    def __init__(self):
        self.chains = []


class Parser:
    CHAIN_TEXT: str = "Chain"

    # TODO: Rename
    CONVERT_TABL: Dict = {'K': 1_000, 'M': 1_000_000, 'G': 1_000_000_000, 'T': 1_000_000_000_000}

    @staticmethod
    def parse(input: List) -> (IPTables, bool):
        ip_table_raw, chain_lines = [], []
        for line in input:
            if line and not line.isspace():
                chain_lines.append(line)
            else:
                if len(chain_lines):
                    ip_table_raw.append(chain_lines)
                chain_lines = []

        ip_tables: IPTables = IPTables()
        for lines in ip_table_raw:
            if 2 > len(lines):
                return ip_tables, False

            chain, ok = Parser.ParseChainLineTest(lines[0])
            if not ok:
                return ip_tables, False

            headers: List[Tuple] = Parser.extract_header(lines[1])
            for idx in range(2, len(lines)):
                chain.rules.append(Parser.extract_rule(headers, lines[idx]))

            ip_tables.chains.append(chain)

        return ip_tables, True

    @staticmethod
    def extract_header(line: str) -> List[Tuple]:
        headers: List[Tuple] = []
        text, start, prev = line[0], 0, ''
        for idx in range(1, len(line)):
            ch = line[idx]
            if ' ' == ch:
                if ' ' != prev:
                    if len(text):
                        headers.append((text.strip(), start))
                    text = ""
            else:
                text += ch
                if ' ' == prev:
                    start = idx
            prev = ch
        headers.append((text, start))

        return headers

    @staticmethod
    def extract_rule(headers: List[Tuple], line: str) -> Dict[str, str] :
        rule: Dict[str, str] = dict()
        prev = headers[0]
        for idx in range(1, len(headers)):
            curr = headers[idx]
            rule[prev[0]] = line[prev[1]: curr[1]].strip()
            prev = curr
        rule[prev[0]] = line[prev[1]:].strip()

        return rule

    @staticmethod
    def ParseInt(value: str) -> int:
        try:
            return int(value)
        except ValueError:
            return int(value[:-1]) * Parser.CONVERT_TABL[value[-1]]

    @staticmethod
    def ParseChainLineTest(line: str) -> (Chain, bool):
        if Parser.CHAIN_TEXT not in line:
            return None, False
        line = line.replace(Parser.CHAIN_TEXT, '').strip()

        pos1 = line.find(' (')
        if -1 == pos1:
            return None, False

        pos2 = line.find(')', pos1)
        if -1 == pos2:
            return None, False

        chain: Chain = Chain(name=line[0: pos1])
        params: List[str] = line[pos1 + 2: pos2].split()
        if 6 != len(params):
            return None, False

        chain.policy = params[1]
        chain.packets = Parser.ParseInt(params[2])
        chain.bytes = Parser.ParseInt(params[4])

        return chain, True


if __name__ == '__main__':
    '''
    # output = Utilities.ExecuteCommand("ls -lar /home/andtokm/DiskS/ProjectsUbuntu/Python/Linux")
    # output = Utilities.ExecuteCommand(" iptables -L -t filter")

    for l in output:
        print(l)
    '''

    tables, ok = Parser.parse(TestData.test_input)
    for chain in tables.chains:
        print(chain)
        print(chain.rules)
        print()


    '''
    # chain, ok = Parser.ParseChainLineTest("Chain POSTROUTING (policy ACCEPT 10 packets, 400 bytes)")
    chain, ok = Parser.ParseChainLineTest("Chain POSTROUTING (policy ACCEPT 10 packets, 400 bytes)")
    print(ok)
    print(chain)
    '''

    '''
    hdr: str = "num   pkts bytes target     prot opt in     out     source               destination"
    val: str = "1     5850  736K MASQUERADE  all  --  *      eth0    0.0.0.0/0            0.0.0.0/0"

    headers: List[Tuple] = []
    text, start, prev = hdr[0], 0, ''
    for idx in range(1, len(hdr)):
        ch = hdr[idx]
        if ' ' == ch:
            if ' ' != prev:
                if len(text):
                    headers.append((text.strip(), start))
                text = ""
        else:
            text += ch
            if ' ' == prev:
                start = idx
        prev = ch
    headers.append((text, start))

    rule: Dict[str, str] = dict()
    prev = headers[0]
    for idx in range(1, len(headers)):
        curr = headers[idx]
        rule[prev[0]] = val[prev[1]: curr[1]].strip()
        prev = curr
    rule[prev[0]] = val[prev[1]:].strip()

    print(rule)
    '''
