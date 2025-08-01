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
    'GetWlmsManagedInstanceResult',
    'AwaitableGetWlmsManagedInstanceResult',
    'get_wlms_managed_instance',
    'get_wlms_managed_instance_output',
]

@pulumi.output_type
class GetWlmsManagedInstanceResult:
    """
    A collection of values returned by getWlmsManagedInstance.
    """
    def __init__(__self__, compartment_id=None, configurations=None, display_name=None, host_name=None, id=None, managed_instance_id=None, os_arch=None, os_name=None, plugin_status=None, server_count=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if configurations and not isinstance(configurations, list):
            raise TypeError("Expected argument 'configurations' to be a list")
        pulumi.set(__self__, "configurations", configurations)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if host_name and not isinstance(host_name, str):
            raise TypeError("Expected argument 'host_name' to be a str")
        pulumi.set(__self__, "host_name", host_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_instance_id and not isinstance(managed_instance_id, str):
            raise TypeError("Expected argument 'managed_instance_id' to be a str")
        pulumi.set(__self__, "managed_instance_id", managed_instance_id)
        if os_arch and not isinstance(os_arch, str):
            raise TypeError("Expected argument 'os_arch' to be a str")
        pulumi.set(__self__, "os_arch", os_arch)
        if os_name and not isinstance(os_name, str):
            raise TypeError("Expected argument 'os_name' to be a str")
        pulumi.set(__self__, "os_name", os_name)
        if plugin_status and not isinstance(plugin_status, str):
            raise TypeError("Expected argument 'plugin_status' to be a str")
        pulumi.set(__self__, "plugin_status", plugin_status)
        if server_count and not isinstance(server_count, int):
            raise TypeError("Expected argument 'server_count' to be a int")
        pulumi.set(__self__, "server_count", server_count)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def configurations(self) -> Sequence['outputs.GetWlmsManagedInstanceConfigurationResult']:
        """
        The configuration for a managed instance.
        """
        return pulumi.get(self, "configurations")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name that does not have to be unique and is changeable.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="hostName")
    def host_name(self) -> _builtins.str:
        """
        The FQDN of the managed instance.
        """
        return pulumi.get(self, "host_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="managedInstanceId")
    def managed_instance_id(self) -> _builtins.str:
        return pulumi.get(self, "managed_instance_id")

    @_builtins.property
    @pulumi.getter(name="osArch")
    def os_arch(self) -> _builtins.str:
        """
        The operating system architecture on the managed instance.
        """
        return pulumi.get(self, "os_arch")

    @_builtins.property
    @pulumi.getter(name="osName")
    def os_name(self) -> _builtins.str:
        """
        The operating system name on the managed instance.
        """
        return pulumi.get(self, "os_name")

    @_builtins.property
    @pulumi.getter(name="pluginStatus")
    def plugin_status(self) -> _builtins.str:
        """
        The plugin status of the managed instance.
        """
        return pulumi.get(self, "plugin_status")

    @_builtins.property
    @pulumi.getter(name="serverCount")
    def server_count(self) -> _builtins.int:
        """
        The number of servers running in the managed instance.
        """
        return pulumi.get(self, "server_count")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the managed instance was first reported (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the managed instance was last report (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetWlmsManagedInstanceResult(GetWlmsManagedInstanceResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetWlmsManagedInstanceResult(
            compartment_id=self.compartment_id,
            configurations=self.configurations,
            display_name=self.display_name,
            host_name=self.host_name,
            id=self.id,
            managed_instance_id=self.managed_instance_id,
            os_arch=self.os_arch,
            os_name=self.os_name,
            plugin_status=self.plugin_status,
            server_count=self.server_count,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_wlms_managed_instance(managed_instance_id: Optional[_builtins.str] = None,
                              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetWlmsManagedInstanceResult:
    """
    This data source provides details about a specific Managed Instance resource in Oracle Cloud Infrastructure Wlms service.

    Gets information about the specified managed instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_instance = oci.oci.get_wlms_managed_instance(managed_instance_id=test_managed_instance_oci_wlms_managed_instance["id"])
    ```


    :param _builtins.str managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    """
    __args__ = dict()
    __args__['managedInstanceId'] = managed_instance_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:oci/getWlmsManagedInstance:getWlmsManagedInstance', __args__, opts=opts, typ=GetWlmsManagedInstanceResult).value

    return AwaitableGetWlmsManagedInstanceResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        configurations=pulumi.get(__ret__, 'configurations'),
        display_name=pulumi.get(__ret__, 'display_name'),
        host_name=pulumi.get(__ret__, 'host_name'),
        id=pulumi.get(__ret__, 'id'),
        managed_instance_id=pulumi.get(__ret__, 'managed_instance_id'),
        os_arch=pulumi.get(__ret__, 'os_arch'),
        os_name=pulumi.get(__ret__, 'os_name'),
        plugin_status=pulumi.get(__ret__, 'plugin_status'),
        server_count=pulumi.get(__ret__, 'server_count'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_wlms_managed_instance_output(managed_instance_id: Optional[pulumi.Input[_builtins.str]] = None,
                                     opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetWlmsManagedInstanceResult]:
    """
    This data source provides details about a specific Managed Instance resource in Oracle Cloud Infrastructure Wlms service.

    Gets information about the specified managed instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_instance = oci.oci.get_wlms_managed_instance(managed_instance_id=test_managed_instance_oci_wlms_managed_instance["id"])
    ```


    :param _builtins.str managed_instance_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
    """
    __args__ = dict()
    __args__['managedInstanceId'] = managed_instance_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:oci/getWlmsManagedInstance:getWlmsManagedInstance', __args__, opts=opts, typ=GetWlmsManagedInstanceResult)
    return __ret__.apply(lambda __response__: GetWlmsManagedInstanceResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        configurations=pulumi.get(__response__, 'configurations'),
        display_name=pulumi.get(__response__, 'display_name'),
        host_name=pulumi.get(__response__, 'host_name'),
        id=pulumi.get(__response__, 'id'),
        managed_instance_id=pulumi.get(__response__, 'managed_instance_id'),
        os_arch=pulumi.get(__response__, 'os_arch'),
        os_name=pulumi.get(__response__, 'os_name'),
        plugin_status=pulumi.get(__response__, 'plugin_status'),
        server_count=pulumi.get(__response__, 'server_count'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
