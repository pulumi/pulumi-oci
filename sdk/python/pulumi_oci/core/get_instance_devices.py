# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetInstanceDevicesResult',
    'AwaitableGetInstanceDevicesResult',
    'get_instance_devices',
    'get_instance_devices_output',
]

@pulumi.output_type
class GetInstanceDevicesResult:
    """
    A collection of values returned by getInstanceDevices.
    """
    def __init__(__self__, devices=None, filters=None, id=None, instance_id=None, is_available=None, name=None):
        if devices and not isinstance(devices, list):
            raise TypeError("Expected argument 'devices' to be a list")
        pulumi.set(__self__, "devices", devices)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_id and not isinstance(instance_id, str):
            raise TypeError("Expected argument 'instance_id' to be a str")
        pulumi.set(__self__, "instance_id", instance_id)
        if is_available and not isinstance(is_available, bool):
            raise TypeError("Expected argument 'is_available' to be a bool")
        pulumi.set(__self__, "is_available", is_available)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)

    @property
    @pulumi.getter
    def devices(self) -> Sequence['outputs.GetInstanceDevicesDeviceResult']:
        """
        The list of devices.
        """
        return pulumi.get(self, "devices")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetInstanceDevicesFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> str:
        return pulumi.get(self, "instance_id")

    @property
    @pulumi.getter(name="isAvailable")
    def is_available(self) -> Optional[bool]:
        """
        The flag denoting whether device is available.
        """
        return pulumi.get(self, "is_available")

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The device name.
        """
        return pulumi.get(self, "name")


class AwaitableGetInstanceDevicesResult(GetInstanceDevicesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstanceDevicesResult(
            devices=self.devices,
            filters=self.filters,
            id=self.id,
            instance_id=self.instance_id,
            is_available=self.is_available,
            name=self.name)


def get_instance_devices(filters: Optional[Sequence[pulumi.InputType['GetInstanceDevicesFilterArgs']]] = None,
                         instance_id: Optional[str] = None,
                         is_available: Optional[bool] = None,
                         name: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstanceDevicesResult:
    """
    This data source provides the list of Instance Devices in Oracle Cloud Infrastructure Core service.

    Gets a list of all the devices for given instance. You can optionally filter results by device availability.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_devices = oci.Core.get_instance_devices(instance_id=oci_core_instance["test_instance"]["id"],
        is_available=var["instance_device_is_available"],
        name=var["instance_device_name"])
    ```


    :param str instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    :param bool is_available: A filter to return only available devices or only used devices.
    :param str name: A filter to return only devices that match the given name exactly.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['instanceId'] = instance_id
    __args__['isAvailable'] = is_available
    __args__['name'] = name
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getInstanceDevices:getInstanceDevices', __args__, opts=opts, typ=GetInstanceDevicesResult).value

    return AwaitableGetInstanceDevicesResult(
        devices=__ret__.devices,
        filters=__ret__.filters,
        id=__ret__.id,
        instance_id=__ret__.instance_id,
        is_available=__ret__.is_available,
        name=__ret__.name)


@_utilities.lift_output_func(get_instance_devices)
def get_instance_devices_output(filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetInstanceDevicesFilterArgs']]]]] = None,
                                instance_id: Optional[pulumi.Input[str]] = None,
                                is_available: Optional[pulumi.Input[Optional[bool]]] = None,
                                name: Optional[pulumi.Input[Optional[str]]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetInstanceDevicesResult]:
    """
    This data source provides the list of Instance Devices in Oracle Cloud Infrastructure Core service.

    Gets a list of all the devices for given instance. You can optionally filter results by device availability.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_devices = oci.Core.get_instance_devices(instance_id=oci_core_instance["test_instance"]["id"],
        is_available=var["instance_device_is_available"],
        name=var["instance_device_name"])
    ```


    :param str instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    :param bool is_available: A filter to return only available devices or only used devices.
    :param str name: A filter to return only devices that match the given name exactly.
    """
    ...