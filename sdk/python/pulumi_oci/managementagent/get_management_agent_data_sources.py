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
    'GetManagementAgentDataSourcesResult',
    'AwaitableGetManagementAgentDataSourcesResult',
    'get_management_agent_data_sources',
    'get_management_agent_data_sources_output',
]

@pulumi.output_type
class GetManagementAgentDataSourcesResult:
    """
    A collection of values returned by getManagementAgentDataSources.
    """
    def __init__(__self__, data_sources=None, filters=None, id=None, management_agent_id=None, name=None):
        if data_sources and not isinstance(data_sources, list):
            raise TypeError("Expected argument 'data_sources' to be a list")
        pulumi.set(__self__, "data_sources", data_sources)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if management_agent_id and not isinstance(management_agent_id, str):
            raise TypeError("Expected argument 'management_agent_id' to be a str")
        pulumi.set(__self__, "management_agent_id", management_agent_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)

    @_builtins.property
    @pulumi.getter(name="dataSources")
    def data_sources(self) -> Sequence['outputs.GetManagementAgentDataSourcesDataSourceResult']:
        """
        The list of data_sources.
        """
        return pulumi.get(self, "data_sources")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetManagementAgentDataSourcesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managementAgentId")
    def management_agent_id(self) -> _builtins.str:
        return pulumi.get(self, "management_agent_id")

    @_builtins.property
    @pulumi.getter
    def name(self) -> Optional[_builtins.str]:
        """
        Unique name of the DataSource.
        """
        return pulumi.get(self, "name")


class AwaitableGetManagementAgentDataSourcesResult(GetManagementAgentDataSourcesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagementAgentDataSourcesResult(
            data_sources=self.data_sources,
            filters=self.filters,
            id=self.id,
            management_agent_id=self.management_agent_id,
            name=self.name)


def get_management_agent_data_sources(filters: Optional[Sequence[Union['GetManagementAgentDataSourcesFilterArgs', 'GetManagementAgentDataSourcesFilterArgsDict']]] = None,
                                      management_agent_id: Optional[_builtins.str] = None,
                                      name: Optional[_builtins.str] = None,
                                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagementAgentDataSourcesResult:
    """
    This data source provides the list of Management Agent Data Sources in Oracle Cloud Infrastructure Management Agent service.

    A list of Management Agent Data Sources for the given Management Agent Id.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_agent_data_sources = oci.ManagementAgent.get_management_agent_data_sources(management_agent_id=test_management_agent["id"],
        name=management_agent_data_source_name)
    ```


    :param _builtins.str management_agent_id: Unique Management Agent identifier
    :param _builtins.str name: Unique name of the dataSource.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managementAgentId'] = management_agent_id
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ManagementAgent/getManagementAgentDataSources:getManagementAgentDataSources', __args__, opts=opts, typ=GetManagementAgentDataSourcesResult).value

    return AwaitableGetManagementAgentDataSourcesResult(
        data_sources=pulumi.get(__ret__, 'data_sources'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        management_agent_id=pulumi.get(__ret__, 'management_agent_id'),
        name=pulumi.get(__ret__, 'name'))
def get_management_agent_data_sources_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetManagementAgentDataSourcesFilterArgs', 'GetManagementAgentDataSourcesFilterArgsDict']]]]] = None,
                                             management_agent_id: Optional[pulumi.Input[_builtins.str]] = None,
                                             name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetManagementAgentDataSourcesResult]:
    """
    This data source provides the list of Management Agent Data Sources in Oracle Cloud Infrastructure Management Agent service.

    A list of Management Agent Data Sources for the given Management Agent Id.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_management_agent_data_sources = oci.ManagementAgent.get_management_agent_data_sources(management_agent_id=test_management_agent["id"],
        name=management_agent_data_source_name)
    ```


    :param _builtins.str management_agent_id: Unique Management Agent identifier
    :param _builtins.str name: Unique name of the dataSource.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['managementAgentId'] = management_agent_id
    __args__['name'] = name
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:ManagementAgent/getManagementAgentDataSources:getManagementAgentDataSources', __args__, opts=opts, typ=GetManagementAgentDataSourcesResult)
    return __ret__.apply(lambda __response__: GetManagementAgentDataSourcesResult(
        data_sources=pulumi.get(__response__, 'data_sources'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        management_agent_id=pulumi.get(__response__, 'management_agent_id'),
        name=pulumi.get(__response__, 'name')))
