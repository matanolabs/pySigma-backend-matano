from typing import Union, Any, ClassVar, Dict, Optional, Tuple, Pattern, List

import os
import re
import sys
import yaml
import json
import black
import textwrap

from sigma.conversion.state import ConversionState
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem, SigmaLogSource
from sigma.conversion.base import TextQueryBackend, ProcessingPipeline
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError

def snake_case(s: str) -> str:
    return "_".join(
        re.sub(
            "([A-Z][a-z]+)",
            r" \1",
            re.sub("([A-Z]+)", r" \1", s.replace("-", " ").replace(".", " ")),
        ).split()
    ).lower()

def mkdir_if_not_exists(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

class MatanoPythonBackend(TextQueryBackend):
    """Matano Python Backend for Sigma"""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = " == "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "True",
        False: "False",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "({field} and {field}.startswith({value}))"
    endswith_expression   : ClassVar[str] = "({field} and {field}.endswith({value}))"
    contains_expression   : ClassVar[str] = "{value} in {field}"
    wildcard_match_expression : ClassVar[str] = "fnmatch({field}, {value})"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    re_expression : ClassVar[str] = "re.match({regex}, {field})"  # Regular expression query as format string with placeholders {field} and {regex}
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped

    # cidr expressions
    cidr_expression : ClassVar[str] = "cidrmatch({field}, '{value}')"    # CIDR expression query as format string with placeholders {field} = {value}

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} is None"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'   # Expression for number value not bound to a field as format string with placeholder {value}
    # unbound_value_re_expression : ClassVar[str] = '_=~{value}'    # Expression for regular expression not bound to a field as format string with placeholder {value}

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression
 
    field_quote = None

    def __init__(self, processing_pipeline: Optional[ProcessingPipeline] = None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)
        self.used_cidr = False

    def escape_and_quote_field(self, field_name : str) -> str:
        val = super().escape_and_quote_field(field_name)
        parts = val.split(".")
        ret = "record"
        for i in range(len(parts)):
            part = parts[i]
            if i == len(parts) - 1:
                ret += f".get('{part}')"
            else:
                ret += f".get('{part}', {{}})"
        return ret

    def convert_condition_field_eq_val_cidr(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        self.used_cidr = True
        return self.cidr_expression.format(field=self.escape_and_quote_field(cond.field), value=str(cond.value.network))

    def convert_value_re(self, r, state: ConversionState):
        val = super().convert_value_re(r, state)
        return "r" + "'" + val + "'"
    
    def is_keywords_detection(self, item: Union[SigmaDetectionItem, SigmaDetection]):
        if isinstance(item, SigmaDetectionItem):
            return item.is_keyword()
        else:
            return any(self.is_keywords_detection(x) for x in item.detection_items)

    def convert_rule(self, rule: SigmaRule, output_format: Optional[str] = None) -> List[Any]:
        for detection in rule.detection.detections.values():
            if self.is_keywords_detection(detection):
                raise SigmaFeatureNotSupportedByBackendError("Backend does not support keywords.")

        return super().convert_rule(rule, output_format)

    def _format_query(self, query: str):
        final_query = """\
import re, ipaddress
from fnmatch import fnmatch
"""

        if self.used_cidr:
            final_query += """\
def cidrmatch(ip, cidr):
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
"""

        final_query += f"""\
def detect(record):
{textwrap.indent("return (" + query + ")", "    ")}
"""
        return black.format_str(final_query, mode=black.FileMode(line_length=100))

    def _format_logsource(self, ls: SigmaLogSource) -> Optional[str]:
        ret = "_".join(
            s for s in (ls.product, ls.category, ls.service) if s is not None
        )
        return ret

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        return self._format_query(query)

    def finalize_output_default(self, queries: List[str]) -> str:
        return list(queries)

    def finalize_query_detection(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        final_query = self._format_query(query)
        title = snake_case(rule.title)

        comment_values = {
            "description": rule.description,
            "id": str(rule.id),
            "level": str(rule.level),
            "status": str(rule.status),
            "author": rule.author,
            "date": str(rule.date),
            "references": rule.references,
        }
        comment_values = { k: v for k,v in comment_values.items() if v is not None }

        comment = yaml.dump(comment_values, indent=4)
        comment = textwrap.indent(comment, "# ")

        ret = {
            "title": title,
            "detection_content": final_query,
            "comment": comment,
            "log_source": self._format_logsource(rule.logsource),
        }
        return ret

    def finalize_output_detection(self, queries: List[Any]):
        "Outputs rules as detection directories for Matano directory"

        ret = []
        for query in queries:
            title = query["title"].replace("/", "_")
            detection_dir = os.path.join(os.getcwd(), title)
            mkdir_if_not_exists(detection_dir)
            with open(os.path.join(detection_dir, "detect.py"), "w") as det_f:
                det_f.write(query["detection_content"])

            log_sources = [query["log_source"]]

            detection_yml_content = f"""\
# This file was generated from a Sigma rule

{query["comment"]}

name: {json.dumps(query["title"])}
log_sources: {json.dumps(log_sources)}
"""

            with open(os.path.join(detection_dir, "detection.yml"), "w") as config_f:
                config_f.write(detection_yml_content)

            ret.append(detection_dir)

        return ret
