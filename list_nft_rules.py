#!/usr/bin/env python3

import argparse
import copy
import json
import nftables
import sys

description = """
List nft rules in order depending on type and hook of chain
"""


class NftTable:
    def __init__(self, name: str, family: str) -> None:
        self.name = name
        self.family = family
        self.chains = []

    def add_chain(self, chain):
        if chain not in self.chains:
            self.chains.append(chain)

    def to_dict(self):
        return {"table": {"name": self.name, "family": self.family}}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name}, {self.family})"

    def __str__(self) -> str:
        return f"table {self.family} {self.name}"

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, self.__class__):
            if self.name == __value.name and self.family == __value.family:
                return True
        return False

    def __hash__(self) -> int:
        return hash(self.__repr__())

    @classmethod
    def from_dict(cls, table: dict):
        name = table["table"].get("name")
        family = table["table"].get("family")
        if not name or not family:
            raise ValueError("Missing required parameter")
        return cls(name, family)


class NftChain:
    def __init__(self, name: str, family: str, table: str, **kwargs) -> None:
        self.name = name
        self.family = family
        self.table = table
        self.rules = []
        self.type = None
        self.hook = None
        if kwargs:
            self.kwargs = kwargs
            for k, v in kwargs.items():
                setattr(self, k, v)

    def add_to_table(self, table: NftTable):
        self.table = table
        self.table.add_chain(self)

    def add_rule(self, rule):
        if rule not in self.rules:
            self.rules.append(rule)

    def to_dict(self):
        ret = {"name": self.name, "family": self.family, "table": self.table}
        if self.kwargs:
            ret = {**ret, **self.kwargs}
        return {"chain": ret}

    def __repr__(self) -> str:
        my_dict = self.to_dict()
        return f"{self.__class__.__name__}({my_dict})"

    def __str__(self) -> str:
        return f"chain {self.name}"

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, self.__class__):
            if (
                self.name == __value.name
                and self.family == __value.family
                and self.table == __value.table
            ):
                return True
        return False

    def __hash__(self) -> int:
        return hash(self.__repr__())

    @classmethod
    def from_dict(cls, chain: dict):
        chain_cp = copy.deepcopy(chain)
        table = chain_cp["chain"].pop("table")
        name = chain_cp["chain"].pop("name")
        family = chain_cp["chain"].pop("family")
        rest = chain_cp["chain"]
        return cls(name, family, table, **rest)


class NftRule:
    def __init__(self, chain, family, table, expr, **kwargs) -> None:
        self.chain = chain
        self.family = family
        self.table = table
        self.expr = expr
        if kwargs:
            self.kwargs = kwargs
            for k, v in kwargs.items():
                setattr(self, k, v)

    def add_to_chain(self, chain: NftChain):
        self.chain = chain
        self.table = chain.table

    def to_dict(self):
        ret = {
            "chain": self.chain,
            "family": self.family,
            "table": self.table,
            "expr": self.expr,
        }
        return {"rule": ret}

    def __repr__(self) -> str:
        my_dict = self.to_dict()
        return f"{self.__class__.__name__}({my_dict})"

    def __str__(self) -> str:
        ret = ""
        for x in self.expr:
            if "meta" in x:
                ret = ret + " meta " + x["meta"]["key"]
            if "match" in x:
                if "meta" in x["match"]["left"]:
                    ret = ret + x["match"]["left"]["meta"]["key"] + " "
                elif "payload" in x["match"]["left"]:
                    ret = ret + x["match"]["left"]["payload"]["protocol"] + " "
                    ret = ret + x["match"]["left"]["payload"]["field"] + " "
                else:
                    ret = ret + str(x["match"]["left"]) + " "
                ret = ret + x["match"]["op"] + " "
                ret = ret + str(x["match"]["right"]) + " "
            if "return" in x:
                ret = ret + " return"
            if "accept" in x:
                ret = ret + " accept"
            if "drop" in x:
                ret = ret + " drop"
            if "reject" in x:
                ret = ret + " reject"
            if "jump" in x:
                ret = ret + "jump " + x["jump"]["target"]
        handle = getattr(self, "handle", None)
        if handle:
            ret = ret + "\t\t# handle : {0}".format(handle)
        return ret

    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, self.__class__):
            if (
                self.chain == __value.chain
                and self.family == __value.family
                and self.table == __value.table
                and self.expr == __value.expr
            ):
                return True
        return False

    def __hash__(self) -> int:
        return hash(self.__repr__())

    @classmethod
    def from_dict(cls, rule):
        rule_cp = copy.deepcopy(rule)
        chain = rule_cp["rule"].pop("chain")
        family = rule_cp["rule"].pop("family")
        table = rule_cp["rule"].pop("table")
        expr = rule_cp["rule"].pop("expr")
        rest = rule_cp["rule"]
        return cls(chain, family, table, expr, **rest)


class NftRuleset:
    hooks = [
        "ingress",
        "prerouting",
        "forward",
        "input",
        "output",
        "postrouting",
        "egress",
    ]
    families = ["netdev", "bridge", "arp", "ip", "ip6", "inet"]
    types = ["filter", "nat", "route"]

    def __init__(self, ruleset) -> None:
        self.ruleset = ruleset
        self.metainfo = {}
        self.tables = []
        self.chains = []
        self.rules = []
        self._tables = []
        self._chains = []
        self._rules = []

        self._init_tables()
        self._init_chains()
        self._init_rules()

    def _init_tables(self) -> None:
        self._tables = [x for x in self.ruleset["nftables"] if x.get("table")]
        for raw_table in self._tables:
            self.tables.append(NftTable.from_dict(raw_table))

    def _init_chains(self) -> None:
        self._chains = [x for x in self.ruleset["nftables"] if x.get("chain")]
        for raw_chain in self._chains:
            self.chains.append(NftChain.from_dict(raw_chain))

    def _init_rules(self) -> None:
        self._rules = [x for x in self.ruleset["nftables"] if x.get("rule")]
        for raw_rule in self._rules:
            self.rules.append(NftRule.from_dict(raw_rule))

    def get_table_for_chain(self, chain) -> NftTable:
        table = [
            x
            for x in self.tables
            if (x.name == chain.table and x.family == chain.family)
        ]
        return table[0]

    def get_chain_for_rule(self, rule) -> NftRule:
        chain = [
            x
            for x in self.chains
            if (
                x.name == rule.chain
                and x.family == rule.family
                and x.table == rule.table
            )
        ]
        return chain[0]

    def get_rules_for_chain(self, chain) -> list[NftRule]:
        rules = [
            x
            for x in self.rules
            if (
                x.family == chain.family
                and x.table == chain.table
                and x.chain == chain.name
            )
        ]
        return rules

    def get_chains_by_name(self, name) -> list[NftChain]:
        return [x for x in self.chains if (x.name == name)]

    def get_chains_by_hook(self, hook) -> list[NftChain]:
        return [x for x in self.chains if (x.hook == hook)]

    def get_chains_by_type(self, type) -> list[NftChain]:
        return [x for x in self.chains if (x.type == type)]

    def get_chain_by_spec(self, name, table, family, type=None, hook=None) -> NftChain:
        chain = [
            x
            for x in self.chains
            if (
                x.name == name
                and x.table == table
                and x.family == family
                and getattr(x, "type", None) == type
                and getattr(x, "hook", None) == hook
            )
        ]
        return chain[0]

    def get_tables_by_name(self, name) -> list[NftTable]:
        return [x for x in self.tables if (x.name == name)]

    def get_table_by_spec(self, name, family) -> NftTable:
        table = [x for x in self.tables if (x.name == name and x.family == family)]
        return table[0]

    def get_tables_by_family(self, family) -> NftTable:
        return [x for x in self.tables if (x.family == family)]

    def __str__(self) -> str:
        ret = ""
        for h in self.hooks:
            ret = ret + "hook: {0}:\n".format(h)
            h_chains = self.get_chains_by_hook(h)
            h_chains = sorted(h_chains, key=lambda x: x.prio)
            for c in h_chains:
                ret = ret + "\ttype: {0}:\n".format(c.type)
                rules = self.get_rules_for_chain(c)
                for r in rules:
                    ret = ret + "{0}\t{1}\trule: {2}\n".format(h, c.name, r)
        return ret


def get_nft_chain(nft, family, table, chain) -> dict:
    cmd = "list chain {0} {1} {2}".format(family, table, chain)
    rc, output, error = nft.cmd(cmd)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print("ERROR: running cmd '{0}'".format(cmd), file=sys.stderr)
        print(error, file=sys.stderr)
        exit(1)
    if len(output) == 0:
        # more error control
        print("ERROR: no output from libnftables", file=sys.stderr)
        exit(0)
    data_structure = json.loads(output)
    return data_structure


def get_ruleset(nft) -> dict:
    cmd = "list ruleset"
    rc, output, error = nft.cmd(cmd)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print("ERROR: running cmd '{0}'".format(cmd), file=sys.stderr)
        print(error, file=sys.stderr)
        exit(1)
    if len(output) == 0:
        # more error control
        print("ERROR: no output from libnftables", file=sys.stderr)
        exit(0)
    data_structure = json.loads(output)
    return data_structure


def resolve_jumps(nft, rule) -> list:
    ret = []
    for exp in rule.expr:
        if "jump" in exp:
            target = exp["jump"]["target"]
            jump_target = get_nft_chain(nft, rule.family, rule.table, target)
            jump_rules = NftRuleset(jump_target)
            for r in jump_rules.rules:
                ret.append(r)
                d = resolve_jumps(nft, r)
                if d:
                    ret.extend(d)
    return ret


def get_arguments():
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-ch",
        "--hook",
        default="input",
        dest="hook",
        help="The hook of chains to list. Default: input",
    )
    parser.add_argument(
        "-t",
        "--chain-type",
        default="filter",
        dest="type",
        help="The type of chains to list. Default: filter",
    )
    return parser.parse_known_args()


def main():
    args, _ = get_arguments()
    chain_type = args.type
    chain_hook = args.hook

    if chain_hook not in NftRuleset.hooks:
        print("Invalid chain hook: {0}".format(chain_hook), file=sys.stderr)
        exit(1)
    if chain_type not in NftRuleset.types:
        print("Invalid chain type: {0}".format(chain_type), file=sys.stderr)
        exit(1)

    nft = nftables.Nftables()
    nft.set_json_output(True)
    nft.set_handle_output(True)
    nft.set_numeric_prio_output(True)
    nft.set_stateless_output(True)

    ruleset = get_ruleset(nft)
    nftrules = NftRuleset(ruleset)

    filter_chains = nftrules.get_chains_by_type(type=chain_type)
    hook_chains = nftrules.get_chains_by_hook(hook=chain_hook)
    relevant_chains = set(filter_chains) & set(hook_chains)

    relevant_chains = sorted(relevant_chains, key=lambda x: x.prio)
    relevant_rules = []
    for chain in relevant_chains:
        rules = nftrules.get_rules_for_chain(chain)
        for rule in rules:
            relevant_rules.append(rule)
            jump_rules = resolve_jumps(nft, rule)
            if jump_rules:
                relevant_rules.extend(jump_rules)

    for index, rule in enumerate(relevant_rules):
        print(index, rule.family, rule.table, rule.chain, rule)


if __name__ == "__main__":
    main()
