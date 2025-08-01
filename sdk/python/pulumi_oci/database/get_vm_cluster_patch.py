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

__all__ = [
    'GetVmClusterPatchResult',
    'AwaitableGetVmClusterPatchResult',
    'get_vm_cluster_patch',
    'get_vm_cluster_patch_output',
]

@pulumi.output_type
class GetVmClusterPatchResult:
    """
    A collection of values returned by getVmClusterPatch.
    """
    def __init__(__self__, available_actions=None, description=None, id=None, last_action=None, lifecycle_details=None, patch_id=None, state=None, time_released=None, version=None, vm_cluster_id=None):
        if available_actions and not isinstance(available_actions, list):
            raise TypeError("Expected argument 'available_actions' to be a list")
        pulumi.set(__self__, "available_actions", available_actions)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if last_action and not isinstance(last_action, str):
            raise TypeError("Expected argument 'last_action' to be a str")
        pulumi.set(__self__, "last_action", last_action)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if patch_id and not isinstance(patch_id, str):
            raise TypeError("Expected argument 'patch_id' to be a str")
        pulumi.set(__self__, "patch_id", patch_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_released and not isinstance(time_released, str):
            raise TypeError("Expected argument 'time_released' to be a str")
        pulumi.set(__self__, "time_released", time_released)
        if version and not isinstance(version, str):
            raise TypeError("Expected argument 'version' to be a str")
        pulumi.set(__self__, "version", version)
        if vm_cluster_id and not isinstance(vm_cluster_id, str):
            raise TypeError("Expected argument 'vm_cluster_id' to be a str")
        pulumi.set(__self__, "vm_cluster_id", vm_cluster_id)

    @_builtins.property
    @pulumi.getter(name="availableActions")
    def available_actions(self) -> Sequence[_builtins.str]:
        """
        Actions that can possibly be performed using this patch.
        """
        return pulumi.get(self, "available_actions")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The text describing this patch package.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lastAction")
    def last_action(self) -> _builtins.str:
        """
        Action that is currently being performed or was completed last.
        """
        return pulumi.get(self, "last_action")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A descriptive text associated with the lifecycleState. Typically can contain additional displayable text.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="patchId")
    def patch_id(self) -> _builtins.str:
        return pulumi.get(self, "patch_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the patch as a result of lastAction.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeReleased")
    def time_released(self) -> _builtins.str:
        """
        The date and time that the patch was released.
        """
        return pulumi.get(self, "time_released")

    @_builtins.property
    @pulumi.getter
    def version(self) -> _builtins.str:
        """
        The version of this patch package.
        """
        return pulumi.get(self, "version")

    @_builtins.property
    @pulumi.getter(name="vmClusterId")
    def vm_cluster_id(self) -> _builtins.str:
        return pulumi.get(self, "vm_cluster_id")


class AwaitableGetVmClusterPatchResult(GetVmClusterPatchResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVmClusterPatchResult(
            available_actions=self.available_actions,
            description=self.description,
            id=self.id,
            last_action=self.last_action,
            lifecycle_details=self.lifecycle_details,
            patch_id=self.patch_id,
            state=self.state,
            time_released=self.time_released,
            version=self.version,
            vm_cluster_id=self.vm_cluster_id)


def get_vm_cluster_patch(patch_id: Optional[_builtins.str] = None,
                         vm_cluster_id: Optional[_builtins.str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVmClusterPatchResult:
    """
    This data source provides details about a specific Vm Cluster Patch resource in Oracle Cloud Infrastructure Database service.

    Gets information about a specified patch package.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patch = oci.Database.get_vm_cluster_patch(patch_id=test_patch["id"],
        vm_cluster_id=test_vm_cluster["id"])
    ```


    :param _builtins.str patch_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
    :param _builtins.str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['patchId'] = patch_id
    __args__['vmClusterId'] = vm_cluster_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getVmClusterPatch:getVmClusterPatch', __args__, opts=opts, typ=GetVmClusterPatchResult).value

    return AwaitableGetVmClusterPatchResult(
        available_actions=pulumi.get(__ret__, 'available_actions'),
        description=pulumi.get(__ret__, 'description'),
        id=pulumi.get(__ret__, 'id'),
        last_action=pulumi.get(__ret__, 'last_action'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        patch_id=pulumi.get(__ret__, 'patch_id'),
        state=pulumi.get(__ret__, 'state'),
        time_released=pulumi.get(__ret__, 'time_released'),
        version=pulumi.get(__ret__, 'version'),
        vm_cluster_id=pulumi.get(__ret__, 'vm_cluster_id'))
def get_vm_cluster_patch_output(patch_id: Optional[pulumi.Input[_builtins.str]] = None,
                                vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetVmClusterPatchResult]:
    """
    This data source provides details about a specific Vm Cluster Patch resource in Oracle Cloud Infrastructure Database service.

    Gets information about a specified patch package.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patch = oci.Database.get_vm_cluster_patch(patch_id=test_patch["id"],
        vm_cluster_id=test_vm_cluster["id"])
    ```


    :param _builtins.str patch_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
    :param _builtins.str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['patchId'] = patch_id
    __args__['vmClusterId'] = vm_cluster_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getVmClusterPatch:getVmClusterPatch', __args__, opts=opts, typ=GetVmClusterPatchResult)
    return __ret__.apply(lambda __response__: GetVmClusterPatchResult(
        available_actions=pulumi.get(__response__, 'available_actions'),
        description=pulumi.get(__response__, 'description'),
        id=pulumi.get(__response__, 'id'),
        last_action=pulumi.get(__response__, 'last_action'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        patch_id=pulumi.get(__response__, 'patch_id'),
        state=pulumi.get(__response__, 'state'),
        time_released=pulumi.get(__response__, 'time_released'),
        version=pulumi.get(__response__, 'version'),
        vm_cluster_id=pulumi.get(__response__, 'vm_cluster_id')))
