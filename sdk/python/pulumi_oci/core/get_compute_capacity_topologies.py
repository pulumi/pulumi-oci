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
    'GetComputeCapacityTopologiesResult',
    'AwaitableGetComputeCapacityTopologiesResult',
    'get_compute_capacity_topologies',
    'get_compute_capacity_topologies_output',
]

@pulumi.output_type
class GetComputeCapacityTopologiesResult:
    """
    A collection of values returned by getComputeCapacityTopologies.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, compute_capacity_topology_collections=None, display_name=None, filters=None, id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_capacity_topology_collections and not isinstance(compute_capacity_topology_collections, list):
            raise TypeError("Expected argument 'compute_capacity_topology_collections' to be a list")
        pulumi.set(__self__, "compute_capacity_topology_collections", compute_capacity_topology_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[_builtins.str]:
        """
        The availability domain of the compute capacity topology.  Example: `Uocm:US-CHICAGO-1-AD-2`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the compute capacity topology.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="computeCapacityTopologyCollections")
    def compute_capacity_topology_collections(self) -> Sequence['outputs.GetComputeCapacityTopologiesComputeCapacityTopologyCollectionResult']:
        """
        The list of compute_capacity_topology_collection.
        """
        return pulumi.get(self, "compute_capacity_topology_collections")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeCapacityTopologiesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetComputeCapacityTopologiesResult(GetComputeCapacityTopologiesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeCapacityTopologiesResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            compute_capacity_topology_collections=self.compute_capacity_topology_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id)


def get_compute_capacity_topologies(availability_domain: Optional[_builtins.str] = None,
                                    compartment_id: Optional[_builtins.str] = None,
                                    display_name: Optional[_builtins.str] = None,
                                    filters: Optional[Sequence[Union['GetComputeCapacityTopologiesFilterArgs', 'GetComputeCapacityTopologiesFilterArgsDict']]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeCapacityTopologiesResult:
    """
    This data source provides the list of Compute Capacity Topologies in Oracle Cloud Infrastructure Core service.

    Lists the compute capacity topologies in the specified compartment. You can filter the list by a compute
    capacity topology display name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_capacity_topologies = oci.Core.get_compute_capacity_topologies(compartment_id=compartment_id,
        availability_domain=compute_capacity_topology_availability_domain,
        display_name=compute_capacity_topology_display_name)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeCapacityTopologies:getComputeCapacityTopologies', __args__, opts=opts, typ=GetComputeCapacityTopologiesResult).value

    return AwaitableGetComputeCapacityTopologiesResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_capacity_topology_collections=pulumi.get(__ret__, 'compute_capacity_topology_collections'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'))
def get_compute_capacity_topologies_output(availability_domain: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                           display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           filters: Optional[pulumi.Input[Optional[Sequence[Union['GetComputeCapacityTopologiesFilterArgs', 'GetComputeCapacityTopologiesFilterArgsDict']]]]] = None,
                                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeCapacityTopologiesResult]:
    """
    This data source provides the list of Compute Capacity Topologies in Oracle Cloud Infrastructure Core service.

    Lists the compute capacity topologies in the specified compartment. You can filter the list by a compute
    capacity topology display name.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_capacity_topologies = oci.Core.get_compute_capacity_topologies(compartment_id=compartment_id,
        availability_domain=compute_capacity_topology_availability_domain,
        display_name=compute_capacity_topology_display_name)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeCapacityTopologies:getComputeCapacityTopologies', __args__, opts=opts, typ=GetComputeCapacityTopologiesResult)
    return __ret__.apply(lambda __response__: GetComputeCapacityTopologiesResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_capacity_topology_collections=pulumi.get(__response__, 'compute_capacity_topology_collections'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id')))
