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
    'GetAgentDataSourcesResult',
    'AwaitableGetAgentDataSourcesResult',
    'get_agent_data_sources',
    'get_agent_data_sources_output',
]

@pulumi.output_type
class GetAgentDataSourcesResult:
    """
    A collection of values returned by getAgentDataSources.
    """
    def __init__(__self__, compartment_id=None, data_source_collections=None, display_name=None, filters=None, id=None, knowledge_base_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if data_source_collections and not isinstance(data_source_collections, list):
            raise TypeError("Expected argument 'data_source_collections' to be a list")
        pulumi.set(__self__, "data_source_collections", data_source_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if knowledge_base_id and not isinstance(knowledge_base_id, str):
            raise TypeError("Expected argument 'knowledge_base_id' to be a str")
        pulumi.set(__self__, "knowledge_base_id", knowledge_base_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="dataSourceCollections")
    def data_source_collections(self) -> Sequence['outputs.GetAgentDataSourcesDataSourceCollectionResult']:
        """
        The list of data_source_collection.
        """
        return pulumi.get(self, "data_source_collections")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAgentDataSourcesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="knowledgeBaseId")
    def knowledge_base_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the parent KnowledgeBase.
        """
        return pulumi.get(self, "knowledge_base_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the data source.
        """
        return pulumi.get(self, "state")


class AwaitableGetAgentDataSourcesResult(GetAgentDataSourcesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAgentDataSourcesResult(
            compartment_id=self.compartment_id,
            data_source_collections=self.data_source_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            knowledge_base_id=self.knowledge_base_id,
            state=self.state)


def get_agent_data_sources(compartment_id: Optional[_builtins.str] = None,
                           display_name: Optional[_builtins.str] = None,
                           filters: Optional[Sequence[Union['GetAgentDataSourcesFilterArgs', 'GetAgentDataSourcesFilterArgsDict']]] = None,
                           knowledge_base_id: Optional[_builtins.str] = None,
                           state: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAgentDataSourcesResult:
    """
    This data source provides the list of Data Sources in Oracle Cloud Infrastructure Generative Ai Agent service.

    **ListDataSources**

    Gets a list of data sources.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_sources = oci.GenerativeAi.get_agent_data_sources(compartment_id=compartment_id,
        display_name=data_source_display_name,
        knowledge_base_id=test_knowledge_base["id"],
        state=data_source_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str knowledge_base_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledge base.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['knowledgeBaseId'] = knowledge_base_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:GenerativeAi/getAgentDataSources:getAgentDataSources', __args__, opts=opts, typ=GetAgentDataSourcesResult).value

    return AwaitableGetAgentDataSourcesResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        data_source_collections=pulumi.get(__ret__, 'data_source_collections'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        knowledge_base_id=pulumi.get(__ret__, 'knowledge_base_id'),
        state=pulumi.get(__ret__, 'state'))
def get_agent_data_sources_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  filters: Optional[pulumi.Input[Optional[Sequence[Union['GetAgentDataSourcesFilterArgs', 'GetAgentDataSourcesFilterArgsDict']]]]] = None,
                                  knowledge_base_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAgentDataSourcesResult]:
    """
    This data source provides the list of Data Sources in Oracle Cloud Infrastructure Generative Ai Agent service.

    **ListDataSources**

    Gets a list of data sources.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_data_sources = oci.GenerativeAi.get_agent_data_sources(compartment_id=compartment_id,
        display_name=data_source_display_name,
        knowledge_base_id=test_knowledge_base["id"],
        state=data_source_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str knowledge_base_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledge base.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['knowledgeBaseId'] = knowledge_base_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:GenerativeAi/getAgentDataSources:getAgentDataSources', __args__, opts=opts, typ=GetAgentDataSourcesResult)
    return __ret__.apply(lambda __response__: GetAgentDataSourcesResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        data_source_collections=pulumi.get(__response__, 'data_source_collections'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        knowledge_base_id=pulumi.get(__response__, 'knowledge_base_id'),
        state=pulumi.get(__response__, 'state')))
