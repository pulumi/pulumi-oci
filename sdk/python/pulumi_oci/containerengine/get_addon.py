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

__all__ = [
    'GetAddonResult',
    'AwaitableGetAddonResult',
    'get_addon',
    'get_addon_output',
]

@pulumi.output_type
class GetAddonResult:
    """
    A collection of values returned by getAddon.
    """
    def __init__(__self__, addon_errors=None, addon_name=None, cluster_id=None, configurations=None, current_installed_version=None, id=None, remove_addon_resources_on_delete=None, state=None, time_created=None, version=None):
        if addon_errors and not isinstance(addon_errors, list):
            raise TypeError("Expected argument 'addon_errors' to be a list")
        pulumi.set(__self__, "addon_errors", addon_errors)
        if addon_name and not isinstance(addon_name, str):
            raise TypeError("Expected argument 'addon_name' to be a str")
        pulumi.set(__self__, "addon_name", addon_name)
        if cluster_id and not isinstance(cluster_id, str):
            raise TypeError("Expected argument 'cluster_id' to be a str")
        pulumi.set(__self__, "cluster_id", cluster_id)
        if configurations and not isinstance(configurations, list):
            raise TypeError("Expected argument 'configurations' to be a list")
        pulumi.set(__self__, "configurations", configurations)
        if current_installed_version and not isinstance(current_installed_version, str):
            raise TypeError("Expected argument 'current_installed_version' to be a str")
        pulumi.set(__self__, "current_installed_version", current_installed_version)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if remove_addon_resources_on_delete and not isinstance(remove_addon_resources_on_delete, bool):
            raise TypeError("Expected argument 'remove_addon_resources_on_delete' to be a bool")
        pulumi.set(__self__, "remove_addon_resources_on_delete", remove_addon_resources_on_delete)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)

    @property
    @pulumi.getter(name="addonErrors")
    def addon_errors(self) -> Sequence['outputs.GetAddonAddonErrorResult']:
        """
        The error info of the addon.
        """
        return pulumi.get(self, "addon_errors")

    @property
    @pulumi.getter(name="addonName")
    def addon_name(self) -> str:
        """
        The name of the addon.
        """
        return pulumi.get(self, "addon_name")

    @property
    @pulumi.getter(name="clusterId")
    def cluster_id(self) -> str:
        return pulumi.get(self, "cluster_id")

    @property
    @pulumi.getter
    def configurations(self) -> Sequence['outputs.GetAddonConfigurationResult']:
        """
        Addon configuration details.
        """
        return pulumi.get(self, "configurations")

    @property
    @pulumi.getter(name="currentInstalledVersion")
    def current_installed_version(self) -> str:
        """
        current installed version of the addon
        """
        return pulumi.get(self, "current_installed_version")

    @property
    @pulumi.getter
    def id(self) -> str:
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="removeAddonResourcesOnDelete")
    def remove_addon_resources_on_delete(self) -> bool:
        return pulumi.get(self, "remove_addon_resources_on_delete")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The state of the addon.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time the cluster was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter
    def version(self) -> str:
        """
        selected addon version, or null indicates autoUpdate
        """
        return pulumi.get(self, "version")


class AwaitableGetAddonResult(GetAddonResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAddonResult(
            addon_errors=self.addon_errors,
            addon_name=self.addon_name,
            cluster_id=self.cluster_id,
            configurations=self.configurations,
            current_installed_version=self.current_installed_version,
            id=self.id,
            remove_addon_resources_on_delete=self.remove_addon_resources_on_delete,
            state=self.state,
            time_created=self.time_created,
            version=self.version)


def get_addon(addon_name: Optional[str] = None,
              cluster_id: Optional[str] = None,
              opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAddonResult:
    """
    This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.

    Get the specified addon for a cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_addon = oci.ContainerEngine.get_addon(addon_name=oci_containerengine_addon["test_addon"]["name"],
        cluster_id=oci_containerengine_cluster["test_cluster"]["id"])
    ```


    :param str addon_name: The name of the addon.
    :param str cluster_id: The OCID of the cluster.
    """
    __args__ = dict()
    __args__['addonName'] = addon_name
    __args__['clusterId'] = cluster_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:ContainerEngine/getAddon:getAddon', __args__, opts=opts, typ=GetAddonResult).value

    return AwaitableGetAddonResult(
        addon_errors=__ret__.addon_errors,
        addon_name=__ret__.addon_name,
        cluster_id=__ret__.cluster_id,
        configurations=__ret__.configurations,
        current_installed_version=__ret__.current_installed_version,
        id=__ret__.id,
        remove_addon_resources_on_delete=__ret__.remove_addon_resources_on_delete,
        state=__ret__.state,
        time_created=__ret__.time_created,
        version=__ret__.version)


@_utilities.lift_output_func(get_addon)
def get_addon_output(addon_name: Optional[pulumi.Input[str]] = None,
                     cluster_id: Optional[pulumi.Input[str]] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetAddonResult]:
    """
    This data source provides details about a specific Addon resource in Oracle Cloud Infrastructure Container Engine service.

    Get the specified addon for a cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_addon = oci.ContainerEngine.get_addon(addon_name=oci_containerengine_addon["test_addon"]["name"],
        cluster_id=oci_containerengine_cluster["test_cluster"]["id"])
    ```


    :param str addon_name: The name of the addon.
    :param str cluster_id: The OCID of the cluster.
    """
    ...