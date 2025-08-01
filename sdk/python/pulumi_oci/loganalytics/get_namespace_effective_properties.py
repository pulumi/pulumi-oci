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
    'GetNamespaceEffectivePropertiesResult',
    'AwaitableGetNamespaceEffectivePropertiesResult',
    'get_namespace_effective_properties',
    'get_namespace_effective_properties_output',
]

@pulumi.output_type
class GetNamespaceEffectivePropertiesResult:
    """
    A collection of values returned by getNamespaceEffectiveProperties.
    """
    def __init__(__self__, agent_id=None, effective_property_collections=None, entity_id=None, filters=None, id=None, is_include_patterns=None, name=None, namespace=None, pattern_id=None, pattern_id_long=None, source_name=None):
        if agent_id and not isinstance(agent_id, str):
            raise TypeError("Expected argument 'agent_id' to be a str")
        pulumi.set(__self__, "agent_id", agent_id)
        if effective_property_collections and not isinstance(effective_property_collections, list):
            raise TypeError("Expected argument 'effective_property_collections' to be a list")
        pulumi.set(__self__, "effective_property_collections", effective_property_collections)
        if entity_id and not isinstance(entity_id, str):
            raise TypeError("Expected argument 'entity_id' to be a str")
        pulumi.set(__self__, "entity_id", entity_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_include_patterns and not isinstance(is_include_patterns, bool):
            raise TypeError("Expected argument 'is_include_patterns' to be a bool")
        pulumi.set(__self__, "is_include_patterns", is_include_patterns)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if pattern_id and not isinstance(pattern_id, int):
            raise TypeError("Expected argument 'pattern_id' to be a int")
        pulumi.set(__self__, "pattern_id", pattern_id)
        if pattern_id_long and not isinstance(pattern_id_long, str):
            raise TypeError("Expected argument 'pattern_id_long' to be a str")
        pulumi.set(__self__, "pattern_id_long", pattern_id_long)
        if source_name and not isinstance(source_name, str):
            raise TypeError("Expected argument 'source_name' to be a str")
        pulumi.set(__self__, "source_name", source_name)

    @_builtins.property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "agent_id")

    @_builtins.property
    @pulumi.getter(name="effectivePropertyCollections")
    def effective_property_collections(self) -> Sequence['outputs.GetNamespaceEffectivePropertiesEffectivePropertyCollectionResult']:
        """
        The list of effective_property_collection.
        """
        return pulumi.get(self, "effective_property_collections")

    @_builtins.property
    @pulumi.getter(name="entityId")
    def entity_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "entity_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetNamespaceEffectivePropertiesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isIncludePatterns")
    def is_include_patterns(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "is_include_patterns")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        The property name.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter
    def namespace(self) -> _builtins.str:
        return pulumi.get(self, "namespace")

    @_builtins.property
    @pulumi.getter(name="patternId")
    def pattern_id(self) -> Optional[_builtins.int]:
        return pulumi.get(self, "pattern_id")

    @_builtins.property
    @pulumi.getter(name="patternIdLong")
    def pattern_id_long(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "pattern_id_long")

    @_builtins.property
    @pulumi.getter(name="sourceName")
    def source_name(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "source_name")


class AwaitableGetNamespaceEffectivePropertiesResult(GetNamespaceEffectivePropertiesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetNamespaceEffectivePropertiesResult(
            agent_id=self.agent_id,
            effective_property_collections=self.effective_property_collections,
            entity_id=self.entity_id,
            filters=self.filters,
            id=self.id,
            is_include_patterns=self.is_include_patterns,
            name=self.name,
            namespace=self.namespace,
            pattern_id=self.pattern_id,
            pattern_id_long=self.pattern_id_long,
            source_name=self.source_name)


def get_namespace_effective_properties(agent_id: Optional[_builtins.str] = None,
                                       entity_id: Optional[_builtins.str] = None,
                                       filters: Optional[Sequence[Union['GetNamespaceEffectivePropertiesFilterArgs', 'GetNamespaceEffectivePropertiesFilterArgsDict']]] = None,
                                       is_include_patterns: Optional[_builtins.bool] = None,
                                       name: Optional[_builtins.str] = None,
                                       namespace: Optional[_builtins.str] = None,
                                       pattern_id: Optional[_builtins.int] = None,
                                       pattern_id_long: Optional[_builtins.str] = None,
                                       source_name: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetNamespaceEffectivePropertiesResult:
    """
    This data source provides the list of Namespace Effective Properties in Oracle Cloud Infrastructure Log Analytics service.

    Returns a list of effective properties for the specified resource.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_effective_properties = oci.LogAnalytics.get_namespace_effective_properties(namespace=namespace_effective_property_namespace,
        agent_id=test_agent["id"],
        entity_id=test_log_analytics_entity["id"],
        is_include_patterns=namespace_effective_property_is_include_patterns,
        name=namespace_effective_property_name,
        pattern_id=test_pattern["id"],
        pattern_id_long=namespace_effective_property_pattern_id_long,
        source_name=namespace_effective_property_source_name)
    ```


    :param _builtins.str agent_id: The agent ocid.
    :param _builtins.str entity_id: The entity ocid.
    :param _builtins.bool is_include_patterns: The include pattern flag.
    :param _builtins.str name: The property name used for filtering.
    :param _builtins.str namespace: The Logging Analytics namespace used for the request.
    :param _builtins.int pattern_id: The pattern id.
    :param _builtins.str pattern_id_long: The pattern id (long).
    :param _builtins.str source_name: The source name.
    """
    __args__ = dict()
    __args__['agentId'] = agent_id
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['isIncludePatterns'] = is_include_patterns
    __args__['name'] = name
    __args__['namespace'] = namespace
    __args__['patternId'] = pattern_id
    __args__['patternIdLong'] = pattern_id_long
    __args__['sourceName'] = source_name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:LogAnalytics/getNamespaceEffectiveProperties:getNamespaceEffectiveProperties', __args__, opts=opts, typ=GetNamespaceEffectivePropertiesResult).value

    return AwaitableGetNamespaceEffectivePropertiesResult(
        agent_id=pulumi.get(__ret__, 'agent_id'),
        effective_property_collections=pulumi.get(__ret__, 'effective_property_collections'),
        entity_id=pulumi.get(__ret__, 'entity_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        is_include_patterns=pulumi.get(__ret__, 'is_include_patterns'),
        name=pulumi.get(__ret__, 'name'),
        namespace=pulumi.get(__ret__, 'namespace'),
        pattern_id=pulumi.get(__ret__, 'pattern_id'),
        pattern_id_long=pulumi.get(__ret__, 'pattern_id_long'),
        source_name=pulumi.get(__ret__, 'source_name'))
def get_namespace_effective_properties_output(agent_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              entity_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetNamespaceEffectivePropertiesFilterArgs', 'GetNamespaceEffectivePropertiesFilterArgsDict']]]]] = None,
                                              is_include_patterns: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                                              name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              namespace: Optional[pulumi.Input[_builtins.str]] = None,
                                              pattern_id: Optional[pulumi.Input[Optional[_builtins.int]]] = None,
                                              pattern_id_long: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              source_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetNamespaceEffectivePropertiesResult]:
    """
    This data source provides the list of Namespace Effective Properties in Oracle Cloud Infrastructure Log Analytics service.

    Returns a list of effective properties for the specified resource.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_namespace_effective_properties = oci.LogAnalytics.get_namespace_effective_properties(namespace=namespace_effective_property_namespace,
        agent_id=test_agent["id"],
        entity_id=test_log_analytics_entity["id"],
        is_include_patterns=namespace_effective_property_is_include_patterns,
        name=namespace_effective_property_name,
        pattern_id=test_pattern["id"],
        pattern_id_long=namespace_effective_property_pattern_id_long,
        source_name=namespace_effective_property_source_name)
    ```


    :param _builtins.str agent_id: The agent ocid.
    :param _builtins.str entity_id: The entity ocid.
    :param _builtins.bool is_include_patterns: The include pattern flag.
    :param _builtins.str name: The property name used for filtering.
    :param _builtins.str namespace: The Logging Analytics namespace used for the request.
    :param _builtins.int pattern_id: The pattern id.
    :param _builtins.str pattern_id_long: The pattern id (long).
    :param _builtins.str source_name: The source name.
    """
    __args__ = dict()
    __args__['agentId'] = agent_id
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['isIncludePatterns'] = is_include_patterns
    __args__['name'] = name
    __args__['namespace'] = namespace
    __args__['patternId'] = pattern_id
    __args__['patternIdLong'] = pattern_id_long
    __args__['sourceName'] = source_name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:LogAnalytics/getNamespaceEffectiveProperties:getNamespaceEffectiveProperties', __args__, opts=opts, typ=GetNamespaceEffectivePropertiesResult)
    return __ret__.apply(lambda __response__: GetNamespaceEffectivePropertiesResult(
        agent_id=pulumi.get(__response__, 'agent_id'),
        effective_property_collections=pulumi.get(__response__, 'effective_property_collections'),
        entity_id=pulumi.get(__response__, 'entity_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        is_include_patterns=pulumi.get(__response__, 'is_include_patterns'),
        name=pulumi.get(__response__, 'name'),
        namespace=pulumi.get(__response__, 'namespace'),
        pattern_id=pulumi.get(__response__, 'pattern_id'),
        pattern_id_long=pulumi.get(__response__, 'pattern_id_long'),
        source_name=pulumi.get(__response__, 'source_name')))
