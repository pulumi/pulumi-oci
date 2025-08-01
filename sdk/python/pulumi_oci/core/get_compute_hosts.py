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
    'GetComputeHostsResult',
    'AwaitableGetComputeHostsResult',
    'get_compute_hosts',
    'get_compute_hosts_output',
]

@pulumi.output_type
class GetComputeHostsResult:
    """
    A collection of values returned by getComputeHosts.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, compute_host_collections=None, compute_host_group_id=None, compute_host_health=None, compute_host_lifecycle_state=None, display_name=None, filters=None, id=None, lifecycle_details=None, network_resource_id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_host_collections and not isinstance(compute_host_collections, list):
            raise TypeError("Expected argument 'compute_host_collections' to be a list")
        pulumi.set(__self__, "compute_host_collections", compute_host_collections)
        if compute_host_group_id and not isinstance(compute_host_group_id, str):
            raise TypeError("Expected argument 'compute_host_group_id' to be a str")
        pulumi.set(__self__, "compute_host_group_id", compute_host_group_id)
        if compute_host_health and not isinstance(compute_host_health, str):
            raise TypeError("Expected argument 'compute_host_health' to be a str")
        pulumi.set(__self__, "compute_host_health", compute_host_health)
        if compute_host_lifecycle_state and not isinstance(compute_host_lifecycle_state, str):
            raise TypeError("Expected argument 'compute_host_lifecycle_state' to be a str")
        pulumi.set(__self__, "compute_host_lifecycle_state", compute_host_lifecycle_state)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, dict):
            raise TypeError("Expected argument 'lifecycle_details' to be a dict")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if network_resource_id and not isinstance(network_resource_id, str):
            raise TypeError("Expected argument 'network_resource_id' to be a str")
        pulumi.set(__self__, "network_resource_id", network_resource_id)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[_builtins.str]:
        """
        The availability domain of the compute host.  Example: `Uocm:US-CHICAGO-1-AD-2`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="computeHostCollections")
    def compute_host_collections(self) -> Sequence['outputs.GetComputeHostsComputeHostCollectionResult']:
        """
        The list of compute_host_collection.
        """
        return pulumi.get(self, "compute_host_collections")

    @_builtins.property
    @pulumi.getter(name="computeHostGroupId")
    def compute_host_group_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
        """
        return pulumi.get(self, "compute_host_group_id")

    @_builtins.property
    @pulumi.getter(name="computeHostHealth")
    def compute_host_health(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compute_host_health")

    @_builtins.property
    @pulumi.getter(name="computeHostLifecycleState")
    def compute_host_lifecycle_state(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compute_host_lifecycle_state")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetComputeHostsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Mapping[str, _builtins.str]:
        """
        A free-form description detailing why the host is in its current state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="networkResourceId")
    def network_resource_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "network_resource_id")


class AwaitableGetComputeHostsResult(GetComputeHostsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeHostsResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            compute_host_collections=self.compute_host_collections,
            compute_host_group_id=self.compute_host_group_id,
            compute_host_health=self.compute_host_health,
            compute_host_lifecycle_state=self.compute_host_lifecycle_state,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            network_resource_id=self.network_resource_id)


def get_compute_hosts(availability_domain: Optional[_builtins.str] = None,
                      compartment_id: Optional[_builtins.str] = None,
                      compute_host_group_id: Optional[_builtins.str] = None,
                      compute_host_health: Optional[_builtins.str] = None,
                      compute_host_lifecycle_state: Optional[_builtins.str] = None,
                      display_name: Optional[_builtins.str] = None,
                      filters: Optional[Sequence[Union['GetComputeHostsFilterArgs', 'GetComputeHostsFilterArgsDict']]] = None,
                      network_resource_id: Optional[_builtins.str] = None,
                      opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeHostsResult:
    """
    This data source provides the list of Compute Hosts in Oracle Cloud Infrastructure Core service.

    Generates a list of summary host details

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_hosts = oci.Core.get_compute_hosts(compartment_id=compartment_id,
        availability_domain=compute_host_availability_domain,
        compute_host_group_id=test_compute_host_group["id"],
        compute_host_health=compute_host_compute_host_health,
        compute_host_lifecycle_state=compute_host_compute_host_lifecycle_state,
        display_name=compute_host_display_name,
        network_resource_id=test_resource["id"])
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str compute_host_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
    :param _builtins.str compute_host_health: A filter to return only ComputeHostSummary resources that match the given Compute Host health State OCID exactly.
    :param _builtins.str compute_host_lifecycle_state: A filter to return only ComputeHostSummary resources that match the given Compute Host lifecycle State OCID exactly.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str network_resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host network resoruce.
           * Customer-unique HPC island ID
           * Customer-unique network block ID
           * Customer-unique local block ID
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['computeHostGroupId'] = compute_host_group_id
    __args__['computeHostHealth'] = compute_host_health
    __args__['computeHostLifecycleState'] = compute_host_lifecycle_state
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['networkResourceId'] = network_resource_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeHosts:getComputeHosts', __args__, opts=opts, typ=GetComputeHostsResult).value

    return AwaitableGetComputeHostsResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_host_collections=pulumi.get(__ret__, 'compute_host_collections'),
        compute_host_group_id=pulumi.get(__ret__, 'compute_host_group_id'),
        compute_host_health=pulumi.get(__ret__, 'compute_host_health'),
        compute_host_lifecycle_state=pulumi.get(__ret__, 'compute_host_lifecycle_state'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        network_resource_id=pulumi.get(__ret__, 'network_resource_id'))
def get_compute_hosts_output(availability_domain: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                             compute_host_group_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             compute_host_health: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             compute_host_lifecycle_state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             filters: Optional[pulumi.Input[Optional[Sequence[Union['GetComputeHostsFilterArgs', 'GetComputeHostsFilterArgsDict']]]]] = None,
                             network_resource_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                             opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeHostsResult]:
    """
    This data source provides the list of Compute Hosts in Oracle Cloud Infrastructure Core service.

    Generates a list of summary host details

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_hosts = oci.Core.get_compute_hosts(compartment_id=compartment_id,
        availability_domain=compute_host_availability_domain,
        compute_host_group_id=test_compute_host_group["id"],
        compute_host_health=compute_host_compute_host_health,
        compute_host_lifecycle_state=compute_host_compute_host_lifecycle_state,
        display_name=compute_host_display_name,
        network_resource_id=test_resource["id"])
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str compute_host_group_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group.
    :param _builtins.str compute_host_health: A filter to return only ComputeHostSummary resources that match the given Compute Host health State OCID exactly.
    :param _builtins.str compute_host_lifecycle_state: A filter to return only ComputeHostSummary resources that match the given Compute Host lifecycle State OCID exactly.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str network_resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host network resoruce.
           * Customer-unique HPC island ID
           * Customer-unique network block ID
           * Customer-unique local block ID
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['computeHostGroupId'] = compute_host_group_id
    __args__['computeHostHealth'] = compute_host_health
    __args__['computeHostLifecycleState'] = compute_host_lifecycle_state
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['networkResourceId'] = network_resource_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeHosts:getComputeHosts', __args__, opts=opts, typ=GetComputeHostsResult)
    return __ret__.apply(lambda __response__: GetComputeHostsResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_host_collections=pulumi.get(__response__, 'compute_host_collections'),
        compute_host_group_id=pulumi.get(__response__, 'compute_host_group_id'),
        compute_host_health=pulumi.get(__response__, 'compute_host_health'),
        compute_host_lifecycle_state=pulumi.get(__response__, 'compute_host_lifecycle_state'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        network_resource_id=pulumi.get(__response__, 'network_resource_id')))
