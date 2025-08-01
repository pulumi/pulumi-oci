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
    'GetDedicatedVmHostInstancesResult',
    'AwaitableGetDedicatedVmHostInstancesResult',
    'get_dedicated_vm_host_instances',
    'get_dedicated_vm_host_instances_output',
]

@pulumi.output_type
class GetDedicatedVmHostInstancesResult:
    """
    A collection of values returned by getDedicatedVmHostInstances.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, dedicated_vm_host_id=None, dedicated_vm_host_instances=None, filters=None, id=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if dedicated_vm_host_id and not isinstance(dedicated_vm_host_id, str):
            raise TypeError("Expected argument 'dedicated_vm_host_id' to be a str")
        pulumi.set(__self__, "dedicated_vm_host_id", dedicated_vm_host_id)
        if dedicated_vm_host_instances and not isinstance(dedicated_vm_host_instances, list):
            raise TypeError("Expected argument 'dedicated_vm_host_instances' to be a list")
        pulumi.set(__self__, "dedicated_vm_host_instances", dedicated_vm_host_instances)
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
        The availability domain the virtual machine instance is running in.  Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the virtual machine instance.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="dedicatedVmHostId")
    def dedicated_vm_host_id(self) -> _builtins.str:
        return pulumi.get(self, "dedicated_vm_host_id")

    @_builtins.property
    @pulumi.getter(name="dedicatedVmHostInstances")
    def dedicated_vm_host_instances(self) -> Sequence['outputs.GetDedicatedVmHostInstancesDedicatedVmHostInstanceResult']:
        """
        The list of dedicated_vm_host_instances.
        """
        return pulumi.get(self, "dedicated_vm_host_instances")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDedicatedVmHostInstancesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")


class AwaitableGetDedicatedVmHostInstancesResult(GetDedicatedVmHostInstancesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDedicatedVmHostInstancesResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            dedicated_vm_host_id=self.dedicated_vm_host_id,
            dedicated_vm_host_instances=self.dedicated_vm_host_instances,
            filters=self.filters,
            id=self.id)


def get_dedicated_vm_host_instances(availability_domain: Optional[_builtins.str] = None,
                                    compartment_id: Optional[_builtins.str] = None,
                                    dedicated_vm_host_id: Optional[_builtins.str] = None,
                                    filters: Optional[Sequence[Union['GetDedicatedVmHostInstancesFilterArgs', 'GetDedicatedVmHostInstancesFilterArgsDict']]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDedicatedVmHostInstancesResult:
    """
    This data source provides the list of Dedicated Vm Hosts Instances in Oracle Cloud Infrastructure Core service.

    Returns the list of instances on the dedicated virtual machine hosts that match the specified criteria.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vm_hosts_instances = oci.Core.get_dedicated_vm_host_instances(compartment_id=compartment_id,
        dedicated_vm_host_id=test_dedicated_vm_host["id"],
        availability_domain=dedicated_vm_hosts_instance_availability_domain)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str dedicated_vm_host_id: The OCID of the dedicated VM host.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['dedicatedVmHostId'] = dedicated_vm_host_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getDedicatedVmHostInstances:getDedicatedVmHostInstances', __args__, opts=opts, typ=GetDedicatedVmHostInstancesResult).value

    return AwaitableGetDedicatedVmHostInstancesResult(
        availability_domain=pulumi.get(__ret__, 'availability_domain'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        dedicated_vm_host_id=pulumi.get(__ret__, 'dedicated_vm_host_id'),
        dedicated_vm_host_instances=pulumi.get(__ret__, 'dedicated_vm_host_instances'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'))
def get_dedicated_vm_host_instances_output(availability_domain: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                           dedicated_vm_host_id: Optional[pulumi.Input[_builtins.str]] = None,
                                           filters: Optional[pulumi.Input[Optional[Sequence[Union['GetDedicatedVmHostInstancesFilterArgs', 'GetDedicatedVmHostInstancesFilterArgsDict']]]]] = None,
                                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDedicatedVmHostInstancesResult]:
    """
    This data source provides the list of Dedicated Vm Hosts Instances in Oracle Cloud Infrastructure Core service.

    Returns the list of instances on the dedicated virtual machine hosts that match the specified criteria.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dedicated_vm_hosts_instances = oci.Core.get_dedicated_vm_host_instances(compartment_id=compartment_id,
        dedicated_vm_host_id=test_dedicated_vm_host["id"],
        availability_domain=dedicated_vm_hosts_instance_availability_domain)
    ```


    :param _builtins.str availability_domain: The name of the availability domain.  Example: `Uocm:PHX-AD-1`
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str dedicated_vm_host_id: The OCID of the dedicated VM host.
    """
    __args__ = dict()
    __args__['availabilityDomain'] = availability_domain
    __args__['compartmentId'] = compartment_id
    __args__['dedicatedVmHostId'] = dedicated_vm_host_id
    __args__['filters'] = filters
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getDedicatedVmHostInstances:getDedicatedVmHostInstances', __args__, opts=opts, typ=GetDedicatedVmHostInstancesResult)
    return __ret__.apply(lambda __response__: GetDedicatedVmHostInstancesResult(
        availability_domain=pulumi.get(__response__, 'availability_domain'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        dedicated_vm_host_id=pulumi.get(__response__, 'dedicated_vm_host_id'),
        dedicated_vm_host_instances=pulumi.get(__response__, 'dedicated_vm_host_instances'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id')))
