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
    'GetAwrHubSourcesResult',
    'AwaitableGetAwrHubSourcesResult',
    'get_awr_hub_sources',
    'get_awr_hub_sources_output',
]

@pulumi.output_type
class GetAwrHubSourcesResult:
    """
    A collection of values returned by getAwrHubSources.
    """
    def __init__(__self__, awr_hub_id=None, awr_hub_source_id=None, awr_hub_source_summary_collections=None, compartment_id=None, filters=None, id=None, name=None, source_types=None, states=None, statuses=None):
        if awr_hub_id and not isinstance(awr_hub_id, str):
            raise TypeError("Expected argument 'awr_hub_id' to be a str")
        pulumi.set(__self__, "awr_hub_id", awr_hub_id)
        if awr_hub_source_id and not isinstance(awr_hub_source_id, str):
            raise TypeError("Expected argument 'awr_hub_source_id' to be a str")
        pulumi.set(__self__, "awr_hub_source_id", awr_hub_source_id)
        if awr_hub_source_summary_collections and not isinstance(awr_hub_source_summary_collections, list):
            raise TypeError("Expected argument 'awr_hub_source_summary_collections' to be a list")
        pulumi.set(__self__, "awr_hub_source_summary_collections", awr_hub_source_summary_collections)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if source_types and not isinstance(source_types, list):
            raise TypeError("Expected argument 'source_types' to be a list")
        pulumi.set(__self__, "source_types", source_types)
        if states and not isinstance(states, list):
            raise TypeError("Expected argument 'states' to be a list")
        pulumi.set(__self__, "states", states)
        if statuses and not isinstance(statuses, list):
            raise TypeError("Expected argument 'statuses' to be a list")
        pulumi.set(__self__, "statuses", statuses)

    @_builtins.property
    @pulumi.getter(name="awrHubId")
    def awr_hub_id(self) -> _builtins.str:
        """
        AWR Hub OCID
        """
        return pulumi.get(self, "awr_hub_id")

    @_builtins.property
    @pulumi.getter(name="awrHubSourceId")
    def awr_hub_source_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "awr_hub_source_id")

    @_builtins.property
    @pulumi.getter(name="awrHubSourceSummaryCollections")
    def awr_hub_source_summary_collections(self) -> Sequence['outputs.GetAwrHubSourcesAwrHubSourceSummaryCollectionResult']:
        """
        The list of awr_hub_source_summary_collection.
        """
        return pulumi.get(self, "awr_hub_source_summary_collections")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAwrHubSourcesFilterResult']]:
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
        The name of the Awr Hub source database.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="sourceTypes")
    def source_types(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "source_types")

    @_builtins.property
    @pulumi.getter
    def states(self) -> Optional[Sequence[_builtins.str]]:
        """
        the current state of the source database
        """
        return pulumi.get(self, "states")

    @_builtins.property
    @pulumi.getter
    def statuses(self) -> Optional[Sequence[_builtins.str]]:
        """
        Indicates the status of a source database in Operations Insights
        """
        return pulumi.get(self, "statuses")


class AwaitableGetAwrHubSourcesResult(GetAwrHubSourcesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAwrHubSourcesResult(
            awr_hub_id=self.awr_hub_id,
            awr_hub_source_id=self.awr_hub_source_id,
            awr_hub_source_summary_collections=self.awr_hub_source_summary_collections,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            name=self.name,
            source_types=self.source_types,
            states=self.states,
            statuses=self.statuses)


def get_awr_hub_sources(awr_hub_id: Optional[_builtins.str] = None,
                        awr_hub_source_id: Optional[_builtins.str] = None,
                        compartment_id: Optional[_builtins.str] = None,
                        filters: Optional[Sequence[Union['GetAwrHubSourcesFilterArgs', 'GetAwrHubSourcesFilterArgsDict']]] = None,
                        name: Optional[_builtins.str] = None,
                        source_types: Optional[Sequence[_builtins.str]] = None,
                        states: Optional[Sequence[_builtins.str]] = None,
                        statuses: Optional[Sequence[_builtins.str]] = None,
                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAwrHubSourcesResult:
    """
    This data source provides the list of Awr Hub Sources in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Awr Hub source objects.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_awr_hub_sources = oci.Opsi.get_awr_hub_sources(awr_hub_id=test_awr_hub["id"],
        awr_hub_source_id=test_awr_hub_source["id"],
        compartment_id=compartment_id,
        name=awr_hub_source_name,
        source_types=awr_hub_source_source_type,
        states=awr_hub_source_state,
        statuses=awr_hub_source_status)
    ```


    :param _builtins.str awr_hub_id: Unique Awr Hub identifier
    :param _builtins.str awr_hub_source_id: Awr Hub source identifier
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str name: Awr Hub source database name
    :param Sequence[_builtins.str] source_types: Filter by one or more database type. Possible values are ADW-S, ATP-S, ADW-D, ATP-D, EXTERNAL-PDB, EXTERNAL-NONCDB.
    :param Sequence[_builtins.str] states: Lifecycle states
    :param Sequence[_builtins.str] statuses: Resource Status
    """
    __args__ = dict()
    __args__['awrHubId'] = awr_hub_id
    __args__['awrHubSourceId'] = awr_hub_source_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['sourceTypes'] = source_types
    __args__['states'] = states
    __args__['statuses'] = statuses
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getAwrHubSources:getAwrHubSources', __args__, opts=opts, typ=GetAwrHubSourcesResult).value

    return AwaitableGetAwrHubSourcesResult(
        awr_hub_id=pulumi.get(__ret__, 'awr_hub_id'),
        awr_hub_source_id=pulumi.get(__ret__, 'awr_hub_source_id'),
        awr_hub_source_summary_collections=pulumi.get(__ret__, 'awr_hub_source_summary_collections'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        name=pulumi.get(__ret__, 'name'),
        source_types=pulumi.get(__ret__, 'source_types'),
        states=pulumi.get(__ret__, 'states'),
        statuses=pulumi.get(__ret__, 'statuses'))
def get_awr_hub_sources_output(awr_hub_id: Optional[pulumi.Input[_builtins.str]] = None,
                               awr_hub_source_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                               compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                               filters: Optional[pulumi.Input[Optional[Sequence[Union['GetAwrHubSourcesFilterArgs', 'GetAwrHubSourcesFilterArgsDict']]]]] = None,
                               name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                               source_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                               states: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                               statuses: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAwrHubSourcesResult]:
    """
    This data source provides the list of Awr Hub Sources in Oracle Cloud Infrastructure Opsi service.

    Gets a list of Awr Hub source objects.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_awr_hub_sources = oci.Opsi.get_awr_hub_sources(awr_hub_id=test_awr_hub["id"],
        awr_hub_source_id=test_awr_hub_source["id"],
        compartment_id=compartment_id,
        name=awr_hub_source_name,
        source_types=awr_hub_source_source_type,
        states=awr_hub_source_state,
        statuses=awr_hub_source_status)
    ```


    :param _builtins.str awr_hub_id: Unique Awr Hub identifier
    :param _builtins.str awr_hub_source_id: Awr Hub source identifier
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str name: Awr Hub source database name
    :param Sequence[_builtins.str] source_types: Filter by one or more database type. Possible values are ADW-S, ATP-S, ADW-D, ATP-D, EXTERNAL-PDB, EXTERNAL-NONCDB.
    :param Sequence[_builtins.str] states: Lifecycle states
    :param Sequence[_builtins.str] statuses: Resource Status
    """
    __args__ = dict()
    __args__['awrHubId'] = awr_hub_id
    __args__['awrHubSourceId'] = awr_hub_source_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['name'] = name
    __args__['sourceTypes'] = source_types
    __args__['states'] = states
    __args__['statuses'] = statuses
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Opsi/getAwrHubSources:getAwrHubSources', __args__, opts=opts, typ=GetAwrHubSourcesResult)
    return __ret__.apply(lambda __response__: GetAwrHubSourcesResult(
        awr_hub_id=pulumi.get(__response__, 'awr_hub_id'),
        awr_hub_source_id=pulumi.get(__response__, 'awr_hub_source_id'),
        awr_hub_source_summary_collections=pulumi.get(__response__, 'awr_hub_source_summary_collections'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        name=pulumi.get(__response__, 'name'),
        source_types=pulumi.get(__response__, 'source_types'),
        states=pulumi.get(__response__, 'states'),
        statuses=pulumi.get(__response__, 'statuses')))
