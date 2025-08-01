# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetNamespaceParserActionsResult',
    'AwaitableGetNamespaceParserActionsResult',
    'get_namespace_parser_actions',
    'get_namespace_parser_actions_output',
]

@pulumi.output_type
class GetNamespaceParserActionsResult:
    """
    A collection of values returned by getNamespaceParserActions.
    """
    def __init__(__self__, action_display_text=None, filters=None, id=None, name=None, namespace=None, parser_action_summary_collections=None):
        if action_display_text and not isinstance(action_display_text, str):
            raise TypeError("Expected argument 'action_display_text' to be a str")
        pulumi.set(__self__, "action_display_text", action_display_text)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if parser_action_summary_collections and not isinstance(parser_action_summary_collections, list):
            raise TypeError("Expected argument 'parser_action_summary_collections' to be a list")
        pulumi.set(__self__, "parser_action_summary_collections", parser_action_summary_collections)

    @_builtins.property
    @pulumi.getter(name="actionDisplayText")
    def action_display_text(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "action_display_text")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNamespaceParserActionsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        The parser action name.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter(name="parserActionSummaryCollections")
    def parser_action_summary_collections(self) -> Sequence['outputs.GetNamespaceParserActionsParserActionSummaryCollectionResult']:
        """
        The list of parser_action_summary_collection.
        """
        return pulumi.get(self, "parser_action_summary_collections")


class AwaitableGetNamespaceParserActionsResult(GetNamespaceParserActionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNamespaceParserActionsResult(
            action_display_text=self.action_display_text,
            filters=self.filters,
            id=self.id,
            name=self.name,
            namespace=self.namespace,
            parser_action_summary_collections=self.parser_action_summary_collections)


def get_namespace_parser_actions(action_display_text: Optional[_builtins.str] = None,
                                 filters: Optional[Sequence[Union['GetNamespaceParserActionsFilterArgs', 'GetNamespaceParserActionsFilterArgsDict']]] = None,
                                 name: Optional[_builtins.str] = None,
                                 namespace: Optional[_builtins.str] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNamespaceParserActionsResult:
    """
    This data source provides the list of Namespace Parser Actions in Oracle Cloud Infrastructure Log Analytics service.

    Returns a list of parser actions. You may limit the number of results and provide sorting order.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_parser_actions = oci.LogAnalytics.get_namespace_parser_actions(namespace=namespace_parser_action_namespace,
        action_display_text=namespace_parser_action_action_display_text,
        name=namespace_parser_action_name)
    ```


    :param _builtins.str action_display_text: The parser action display text used for filtering.
    :param _builtins.str name: The parser action name used for filtering.
    :param _builtins.str namespace: The Logging Analytics namespace used for the request.
    """
    __args__ = dict()
    __args__['actionDisplayText'] = action_display_text
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LogAnalytics/getNamespaceParserActions:getNamespaceParserActions', __args__, opts=opts, typ=GetNamespaceParserActionsResult).value

    return AwaitableGetNamespaceParserActionsResult(
        action_display_text=pulumi.get(__ret__, 'action_display_text'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        namespace=pulumi.get(__ret__, 'namespace'),
        parser_action_summary_collections=pulumi.get(__ret__, 'parser_action_summary_collections'))
def get_namespace_parser_actions_output(action_display_text: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                        filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNamespaceParserActionsFilterArgs', 'GetNamespaceParserActionsFilterArgsDict']]]]] = None,
                                        name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                        namespace: Optional[pulumi.Input[_builtins.str]] = None,
                                        opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNamespaceParserActionsResult]:
    """
    This data source provides the list of Namespace Parser Actions in Oracle Cloud Infrastructure Log Analytics service.

    Returns a list of parser actions. You may limit the number of results and provide sorting order.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_parser_actions = oci.LogAnalytics.get_namespace_parser_actions(namespace=namespace_parser_action_namespace,
        action_display_text=namespace_parser_action_action_display_text,
        name=namespace_parser_action_name)
    ```


    :param _builtins.str action_display_text: The parser action display text used for filtering.
    :param _builtins.str name: The parser action name used for filtering.
    :param _builtins.str namespace: The Logging Analytics namespace used for the request.
    """
    __args__ = dict()
    __args__['actionDisplayText'] = action_display_text
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['namespace'] = namespace
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LogAnalytics/getNamespaceParserActions:getNamespaceParserActions', __args__, opts=opts, typ=GetNamespaceParserActionsResult)
    return __ret__.apply(lambda __response__: GetNamespaceParserActionsResult(
        action_display_text=pulumi.get(__response__, 'action_display_text'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        namespace=pulumi.get(__response__, 'namespace'),
        parser_action_summary_collections=pulumi.get(__response__, 'parser_action_summary_collections')))
