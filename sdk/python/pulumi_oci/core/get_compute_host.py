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

__all__ = [
    'GetComputeHostResult',
    'AwaitableGetComputeHostResult',
    'get_compute_host',
    'get_compute_host_output',
]

@pulumi.output_type
class GetComputeHostResult:
    """
    A collection of values returned by getComputeHost.
    """
    def __init__(__self__, additional_data=None, availability_domain=None, capacity_reservation_id=None, compartment_id=None, compute_host_group_id=None, compute_host_id=None, configuration_datas=None, configuration_state=None, defined_tags=None, display_name=None, fault_domain=None, freeform_tags=None, gpu_memory_fabric_id=None, health=None, hpc_island_id=None, id=None, impacted_component_details=None, instance_id=None, lifecycle_details=None, local_block_id=None, network_block_id=None, recycle_details=None, shape=None, state=None, time_configuration_check=None, time_created=None, time_updated=None):
        if additional_data and not isinstance(additional_data, str):
            raise TypeError("Expected argument 'additional_data' to be a str")
        pulumi.set(__self__, "additional_data", additional_data)
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if capacity_reservation_id and not isinstance(capacity_reservation_id, str):
            raise TypeError("Expected argument 'capacity_reservation_id' to be a str")
        pulumi.set(__self__, "capacity_reservation_id", capacity_reservation_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_host_group_id and not isinstance(compute_host_group_id, str):
            raise TypeError("Expected argument 'compute_host_group_id' to be a str")
        pulumi.set(__self__, "compute_host_group_id", compute_host_group_id)
        if compute_host_id and not isinstance(compute_host_id, str):
            raise TypeError("Expected argument 'compute_host_id' to be a str")
        pulumi.set(__self__, "compute_host_id", compute_host_id)
        if configuration_datas and not isinstance(configuration_datas, list):
            raise TypeError("Expected argument 'configuration_datas' to be a list")
        pulumi.set(__self__, "configuration_datas", configuration_datas)
        if configuration_state and not isinstance(configuration_state, str):
            raise TypeError("Expected argument 'configuration_state' to be a str")
        pulumi.set(__self__, "configuration_state", configuration_state)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if fault_domain and not isinstance(fault_domain, str):
            raise TypeError("Expected argument 'fault_domain' to be a str")
        pulumi.set(__self__, "fault_domain", fault_domain)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if gpu_memory_fabric_id and not isinstance(gpu_memory_fabric_id, str):
            raise TypeError("Expected argument 'gpu_memory_fabric_id' to be a str")
        pulumi.set(__self__, "gpu_memory_fabric_id", gpu_memory_fabric_id)
        if health and not isinstance(health, str):
            raise TypeError("Expected argument 'health' to be a str")
        pulumi.set(__self__, "health", health)
        if hpc_island_id and not isinstance(hpc_island_id, str):
            raise TypeError("Expected argument 'hpc_island_id' to be a str")
        pulumi.set(__self__, "hpc_island_id", hpc_island_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if impacted_component_details and not isinstance(impacted_component_details, str):
            raise TypeError("Expected argument 'impacted_component_details' to be a str")
        pulumi.set(__self__, "impacted_component_details", impacted_component_details)
        if instance_id and not isinstance(instance_id, str):
            raise TypeError("Expected argument 'instance_id' to be a str")
        pulumi.set(__self__, "instance_id", instance_id)
        if lifecycle_details and not isinstance(lifecycle_details, dict):
            raise TypeError("Expected argument 'lifecycle_details' to be a dict")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if local_block_id and not isinstance(local_block_id, str):
            raise TypeError("Expected argument 'local_block_id' to be a str")
        pulumi.set(__self__, "local_block_id", local_block_id)
        if network_block_id and not isinstance(network_block_id, str):
            raise TypeError("Expected argument 'network_block_id' to be a str")
        pulumi.set(__self__, "network_block_id", network_block_id)
        if recycle_details and not isinstance(recycle_details, list):
            raise TypeError("Expected argument 'recycle_details' to be a list")
        pulumi.set(__self__, "recycle_details", recycle_details)
        if shape and not isinstance(shape, str):
            raise TypeError("Expected argument 'shape' to be a str")
        pulumi.set(__self__, "shape", shape)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_configuration_check and not isinstance(time_configuration_check, str):
            raise TypeError("Expected argument 'time_configuration_check' to be a str")
        pulumi.set(__self__, "time_configuration_check", time_configuration_check)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="additionalData")
    def additional_data(self) -> _builtins.str:
        """
        Additional data that can be exposed to the customer.  Will include raw fault codes for strategic customers
        """
        return pulumi.get(self, "additional_data")

    @_builtins.property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> _builtins.str:
        """
        The availability domain of the compute host.  Example: `Uocm:US-CHICAGO-1-AD-2`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="capacityReservationId")
    def capacity_reservation_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Capacity Reserver that is currently on host
        """
        return pulumi.get(self, "capacity_reservation_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment. This should always be the root compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="computeHostGroupId")
    def compute_host_group_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host group this host was attached to at the time of recycle.
        """
        return pulumi.get(self, "compute_host_group_id")

    @_builtins.property
    @pulumi.getter(name="computeHostId")
    def compute_host_id(self) -> _builtins.str:
        return pulumi.get(self, "compute_host_id")

    @_builtins.property
    @pulumi.getter(name="configurationDatas")
    def configuration_datas(self) -> Sequence['outputs.GetComputeHostConfigurationDataResult']:
        """
        Compute Host Configuration Data
        """
        return pulumi.get(self, "configuration_datas")

    @_builtins.property
    @pulumi.getter(name="configurationState")
    def configuration_state(self) -> _builtins.str:
        """
        Configuration state of the Compute Bare Metal Host.
        """
        return pulumi.get(self, "configuration_state")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="faultDomain")
    def fault_domain(self) -> _builtins.str:
        """
        A fault domain is a grouping of hardware and infrastructure within an availability domain. Each availability domain contains three fault domains. Fault domains let you distribute your instances so that they are not on the same physical hardware within a single availability domain. A hardware failure or Compute hardware maintenance that affects one fault domain does not affect instances in other fault domains.
        """
        return pulumi.get(self, "fault_domain")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="gpuMemoryFabricId")
    def gpu_memory_fabric_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique GPU Memory Fabric
        """
        return pulumi.get(self, "gpu_memory_fabric_id")

    @_builtins.property
    @pulumi.getter
    def health(self) -> _builtins.str:
        """
        The heathy state of the host
        """
        return pulumi.get(self, "health")

    @_builtins.property
    @pulumi.getter(name="hpcIslandId")
    def hpc_island_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique HPC Island
        """
        return pulumi.get(self, "hpc_island_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="impactedComponentDetails")
    def impacted_component_details(self) -> _builtins.str:
        """
        A list that contains impacted components related to an unhealthy host. An impacted component will be a  free-form structure of key values pairs that will provide more or less details based on data tiering
        """
        return pulumi.get(self, "impacted_component_details")

    @_builtins.property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> _builtins.str:
        """
        The public [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Virtual Machine or Bare Metal instance
        """
        return pulumi.get(self, "instance_id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> Mapping[str, _builtins.str]:
        """
        A free-form description detailing why the host is in its current state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="localBlockId")
    def local_block_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Local Block
        """
        return pulumi.get(self, "local_block_id")

    @_builtins.property
    @pulumi.getter(name="networkBlockId")
    def network_block_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for Customer-unique Network Block
        """
        return pulumi.get(self, "network_block_id")

    @_builtins.property
    @pulumi.getter(name="recycleDetails")
    def recycle_details(self) -> Sequence['outputs.GetComputeHostRecycleDetailResult']:
        """
        Shows details about the last recycle performed on this host.
        """
        return pulumi.get(self, "recycle_details")

    @_builtins.property
    @pulumi.getter
    def shape(self) -> _builtins.str:
        """
        The shape of host
        """
        return pulumi.get(self, "shape")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The lifecycle state of the host
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeConfigurationCheck")
    def time_configuration_check(self) -> _builtins.str:
        """
        The date and time that the compute bare metal host configuration check was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_configuration_check")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time that the compute host record was created, in the format defined by [RFC3339](https://tools .ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time that the compute host record was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetComputeHostResult(GetComputeHostResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetComputeHostResult(
            additional_data=self.additional_data,
            availability_domain=self.availability_domain,
            capacity_reservation_id=self.capacity_reservation_id,
            compartment_id=self.compartment_id,
            compute_host_group_id=self.compute_host_group_id,
            compute_host_id=self.compute_host_id,
            configuration_datas=self.configuration_datas,
            configuration_state=self.configuration_state,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            fault_domain=self.fault_domain,
            freeform_tags=self.freeform_tags,
            gpu_memory_fabric_id=self.gpu_memory_fabric_id,
            health=self.health,
            hpc_island_id=self.hpc_island_id,
            id=self.id,
            impacted_component_details=self.impacted_component_details,
            instance_id=self.instance_id,
            lifecycle_details=self.lifecycle_details,
            local_block_id=self.local_block_id,
            network_block_id=self.network_block_id,
            recycle_details=self.recycle_details,
            shape=self.shape,
            state=self.state,
            time_configuration_check=self.time_configuration_check,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_compute_host(compute_host_id: Optional[_builtins.str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetComputeHostResult:
    """
    This data source provides details about a specific Compute Host resource in Oracle Cloud Infrastructure Core service.

    Gets information about the specified compute host

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_host = oci.Core.get_compute_host(compute_host_id=test_compute_host_oci_core_compute_host["id"])
    ```


    :param _builtins.str compute_host_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host.
    """
    __args__ = dict()
    __args__['computeHostId'] = compute_host_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getComputeHost:getComputeHost', __args__, opts=opts, typ=GetComputeHostResult).value

    return AwaitableGetComputeHostResult(
        additional_data=pulumi.get(__ret__, 'additional_data'),
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        capacity_reservation_id=pulumi.get(__ret__, 'capacity_reservation_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_host_group_id=pulumi.get(__ret__, 'compute_host_group_id'),
        compute_host_id=pulumi.get(__ret__, 'compute_host_id'),
        configuration_datas=pulumi.get(__ret__, 'configuration_datas'),
        configuration_state=pulumi.get(__ret__, 'configuration_state'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        display_name=pulumi.get(__ret__, 'display_name'),
        fault_domain=pulumi.get(__ret__, 'fault_domain'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        gpu_memory_fabric_id=pulumi.get(__ret__, 'gpu_memory_fabric_id'),
        health=pulumi.get(__ret__, 'health'),
        hpc_island_id=pulumi.get(__ret__, 'hpc_island_id'),
        id=pulumi.get(__ret__, 'id'),
        impacted_component_details=pulumi.get(__ret__, 'impacted_component_details'),
        instance_id=pulumi.get(__ret__, 'instance_id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        local_block_id=pulumi.get(__ret__, 'local_block_id'),
        network_block_id=pulumi.get(__ret__, 'network_block_id'),
        recycle_details=pulumi.get(__ret__, 'recycle_details'),
        shape=pulumi.get(__ret__, 'shape'),
        state=pulumi.get(__ret__, 'state'),
        time_configuration_check=pulumi.get(__ret__, 'time_configuration_check'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_compute_host_output(compute_host_id: Optional[pulumi.Input[_builtins.str]] = None,
                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetComputeHostResult]:
    """
    This data source provides details about a specific Compute Host resource in Oracle Cloud Infrastructure Core service.

    Gets information about the specified compute host

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_compute_host = oci.Core.get_compute_host(compute_host_id=test_compute_host_oci_core_compute_host["id"])
    ```


    :param _builtins.str compute_host_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute host.
    """
    __args__ = dict()
    __args__['computeHostId'] = compute_host_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getComputeHost:getComputeHost', __args__, opts=opts, typ=GetComputeHostResult)
    return __ret__.apply(lambda __response__: GetComputeHostResult(
        additional_data=pulumi.get(__response__, 'additional_data'),
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        capacity_reservation_id=pulumi.get(__response__, 'capacity_reservation_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_host_group_id=pulumi.get(__response__, 'compute_host_group_id'),
        compute_host_id=pulumi.get(__response__, 'compute_host_id'),
        configuration_datas=pulumi.get(__response__, 'configuration_datas'),
        configuration_state=pulumi.get(__response__, 'configuration_state'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        display_name=pulumi.get(__response__, 'display_name'),
        fault_domain=pulumi.get(__response__, 'fault_domain'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        gpu_memory_fabric_id=pulumi.get(__response__, 'gpu_memory_fabric_id'),
        health=pulumi.get(__response__, 'health'),
        hpc_island_id=pulumi.get(__response__, 'hpc_island_id'),
        id=pulumi.get(__response__, 'id'),
        impacted_component_details=pulumi.get(__response__, 'impacted_component_details'),
        instance_id=pulumi.get(__response__, 'instance_id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        local_block_id=pulumi.get(__response__, 'local_block_id'),
        network_block_id=pulumi.get(__response__, 'network_block_id'),
        recycle_details=pulumi.get(__response__, 'recycle_details'),
        shape=pulumi.get(__response__, 'shape'),
        state=pulumi.get(__response__, 'state'),
        time_configuration_check=pulumi.get(__response__, 'time_configuration_check'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
