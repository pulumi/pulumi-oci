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
    'GetBlockVolumeReplicasResult',
    'AwaitableGetBlockVolumeReplicasResult',
    'get_block_volume_replicas',
    'get_block_volume_replicas_output',
]

@pulumi.output_type
class GetBlockVolumeReplicasResult:
    """
    A collection of values returned by getBlockVolumeReplicas.
    """
    def __init__(__self__, availability_domain=None, block_volume_replicas=None, compartment_id=None, display_name=None, filters=None, id=None, state=None, volume_group_replica_id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if block_volume_replicas and not isinstance(block_volume_replicas, list):
            raise TypeError("Expected argument 'block_volume_replicas' to be a list")
        pulumi.set(__self__, "block_volume_replicas", block_volume_replicas)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if volume_group_replica_id and not isinstance(volume_group_replica_id, str):
            raise TypeError("Expected argument 'volume_group_replica_id' to be a str")
        pulumi.set(__self__, "volume_group_replica_id", volume_group_replica_id)

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> Optional[_builtins.str]:
        """
        The availability domain of the block volume replica.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="blockVolumeReplicas")
    def block_volume_replicas(self) -> Sequence['outputs.GetBlockVolumeReplicasBlockVolumeReplicaResult']:
        """
        The list of block_volume_replicas.
        """
        return pulumi.get(self, "block_volume_replicas")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the compartment that contains the block volume replica.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetBlockVolumeReplicasFilterResult']]:
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
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of a block volume replica.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="volumeGroupReplicaId")
    def volume_group_replica_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "volume_group_replica_id")


class AwaitableGetBlockVolumeReplicasResult(GetBlockVolumeReplicasResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBlockVolumeReplicasResult(
            availability_domain=self.availability_domain,
            block_volume_replicas=self.block_volume_replicas,
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            state=self.state,
            volume_group_replica_id=self.volume_group_replica_id)


def get_block_volume_replicas(availability_domain: Optional[_builtins.str] = None,
                              compartment_id: Optional[_builtins.str] = None,
                              display_name: Optional[_builtins.str] = None,
                              filters: Optional[Sequence[Union['GetBlockVolumeReplicasFilterArgs', 'GetBlockVolumeReplicasFilterArgsDict']]] = None,
                              state: Optional[_builtins.str] = None,
                              volume_group_replica_id: Optional[_builtins.str] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBlockVolumeReplicasResult:
    """
    This data source provides the list of Block Volume Replicas in Oracle Cloud Infrastructure Core service.

    Lists the block volume replicas in the specified compartment and availability domain.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_block_volume_replicas = oci.Core.get_block_volume_replicas(availability_domain=block_volume_replica_availability_domain,
        compartment_id=compartment_id,
        display_name=block_volume_replica_display_name,
        state=block_volume_replica_state,
        volume_group_replica_id=test_volume_group_replica["id"])
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
    :param _builtins.str volume_group_replica_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the volume group replica.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    __args__['volumeGroupReplicaId'] = volume_group_replica_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getBlockVolumeReplicas:getBlockVolumeReplicas', __args__, opts=opts, typ=GetBlockVolumeReplicasResult).value

    return AwaitableGetBlockVolumeReplicasResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        block_volume_replicas=pulumi.get(__ret__, 'block_volume_replicas'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        state=pulumi.get(__ret__, 'state'),
        volume_group_replica_id=pulumi.get(__ret__, 'volume_group_replica_id'))
def get_block_volume_replicas_output(availability_domain: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                     compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                     display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                     filters: Optional[pulumi.Input[Optional[Sequence[Union['GetBlockVolumeReplicasFilterArgs', 'GetBlockVolumeReplicasFilterArgsDict']]]]] = None,
                                     state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                     volume_group_replica_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBlockVolumeReplicasResult]:
    """
    This data source provides the list of Block Volume Replicas in Oracle Cloud Infrastructure Core service.

    Lists the block volume replicas in the specified compartment and availability domain.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_block_volume_replicas = oci.Core.get_block_volume_replicas(availability_domain=block_volume_replica_availability_domain,
        compartment_id=compartment_id,
        display_name=block_volume_replica_display_name,
        state=block_volume_replica_state,
        volume_group_replica_id=test_volume_group_replica["id"])
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
    :param _builtins.str volume_group_replica_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the volume group replica.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['state'] = state
    __args__['volumeGroupReplicaId'] = volume_group_replica_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getBlockVolumeReplicas:getBlockVolumeReplicas', __args__, opts=opts, typ=GetBlockVolumeReplicasResult)
    return __ret__.apply(lambda __response__: GetBlockVolumeReplicasResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        block_volume_replicas=pulumi.get(__response__, 'block_volume_replicas'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        state=pulumi.get(__response__, 'state'),
        volume_group_replica_id=pulumi.get(__response__, 'volume_group_replica_id')))
