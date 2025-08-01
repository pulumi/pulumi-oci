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
    'GetVmClusterPatchHistoryEntryResult',
    'AwaitableGetVmClusterPatchHistoryEntryResult',
    'get_vm_cluster_patch_history_entry',
    'get_vm_cluster_patch_history_entry_output',
]

@pulumi.output_type
class GetVmClusterPatchHistoryEntryResult:
    """
    A collection of values returned by getVmClusterPatchHistoryEntry.
    """
    def __init__(__self__, action=None, id=None, lifecycle_details=None, patch_history_entry_id=None, patch_id=None, state=None, time_ended=None, time_started=None, vm_cluster_id=None):
        if action and not isinstance(action, str):
            raise TypeError("Expected argument 'action' to be a str")
        pulumi.set(__self__, "action", action)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if patch_history_entry_id and not isinstance(patch_history_entry_id, str):
            raise TypeError("Expected argument 'patch_history_entry_id' to be a str")
        pulumi.set(__self__, "patch_history_entry_id", patch_history_entry_id)
        if patch_id and not isinstance(patch_id, str):
            raise TypeError("Expected argument 'patch_id' to be a str")
        pulumi.set(__self__, "patch_id", patch_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_ended and not isinstance(time_ended, str):
            raise TypeError("Expected argument 'time_ended' to be a str")
        pulumi.set(__self__, "time_ended", time_ended)
        if time_started and not isinstance(time_started, str):
            raise TypeError("Expected argument 'time_started' to be a str")
        pulumi.set(__self__, "time_started", time_started)
        if vm_cluster_id and not isinstance(vm_cluster_id, str):
            raise TypeError("Expected argument 'vm_cluster_id' to be a str")
        pulumi.set(__self__, "vm_cluster_id", vm_cluster_id)

    @_builtins.property
    @pulumi.getter
    def action(self) -> _builtins.str:
        """
        The action being performed or was completed.
        """
        return pulumi.get(self, "action")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A descriptive text associated with the lifecycleState. Typically contains additional displayable text.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="patchHistoryEntryId")
    def patch_history_entry_id(self) -> _builtins.str:
        return pulumi.get(self, "patch_history_entry_id")

    @_builtins.property
    @pulumi.getter(name="patchId")
    def patch_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch.
        """
        return pulumi.get(self, "patch_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the action.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeEnded")
    def time_ended(self) -> _builtins.str:
        """
        The date and time when the patch action completed
        """
        return pulumi.get(self, "time_ended")

    @_builtins.property
    @pulumi.getter(name="timeStarted")
    def time_started(self) -> _builtins.str:
        """
        The date and time when the patch action started.
        """
        return pulumi.get(self, "time_started")

    @_builtins.property
    @pulumi.getter(name="vmClusterId")
    def vm_cluster_id(self) -> _builtins.str:
        return pulumi.get(self, "vm_cluster_id")


class AwaitableGetVmClusterPatchHistoryEntryResult(GetVmClusterPatchHistoryEntryResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetVmClusterPatchHistoryEntryResult(
            action=self.action,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            patch_history_entry_id=self.patch_history_entry_id,
            patch_id=self.patch_id,
            state=self.state,
            time_ended=self.time_ended,
            time_started=self.time_started,
            vm_cluster_id=self.vm_cluster_id)


def get_vm_cluster_patch_history_entry(patch_history_entry_id: Optional[_builtins.str] = None,
                                       vm_cluster_id: Optional[_builtins.str] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetVmClusterPatchHistoryEntryResult:
    """
    This data source provides details about a specific Vm Cluster Patch History Entry resource in Oracle Cloud Infrastructure Database service.

    Gets the patch history details for the specified patch history entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patch_history_entry = oci.Database.get_vm_cluster_patch_history_entry(patch_history_entry_id=test_patch_history_entry["id"],
        vm_cluster_id=test_vm_cluster["id"])
    ```


    :param _builtins.str patch_history_entry_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch history entry.
    :param _builtins.str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['patchHistoryEntryId'] = patch_history_entry_id
    __args__['vmClusterId'] = vm_cluster_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getVmClusterPatchHistoryEntry:getVmClusterPatchHistoryEntry', __args__, opts=opts, typ=GetVmClusterPatchHistoryEntryResult).value

    return AwaitableGetVmClusterPatchHistoryEntryResult(
        action=pulumi.get(__ret__, 'action'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        patch_history_entry_id=pulumi.get(__ret__, 'patch_history_entry_id'),
        patch_id=pulumi.get(__ret__, 'patch_id'),
        state=pulumi.get(__ret__, 'state'),
        time_ended=pulumi.get(__ret__, 'time_ended'),
        time_started=pulumi.get(__ret__, 'time_started'),
        vm_cluster_id=pulumi.get(__ret__, 'vm_cluster_id'))
def get_vm_cluster_patch_history_entry_output(patch_history_entry_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetVmClusterPatchHistoryEntryResult]:
    """
    This data source provides details about a specific Vm Cluster Patch History Entry resource in Oracle Cloud Infrastructure Database service.

    Gets the patch history details for the specified patch history entry.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_vm_cluster_patch_history_entry = oci.Database.get_vm_cluster_patch_history_entry(patch_history_entry_id=test_patch_history_entry["id"],
        vm_cluster_id=test_vm_cluster["id"])
    ```


    :param _builtins.str patch_history_entry_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the patch history entry.
    :param _builtins.str vm_cluster_id: The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['patchHistoryEntryId'] = patch_history_entry_id
    __args__['vmClusterId'] = vm_cluster_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getVmClusterPatchHistoryEntry:getVmClusterPatchHistoryEntry', __args__, opts=opts, typ=GetVmClusterPatchHistoryEntryResult)
    return __ret__.apply(lambda __response__: GetVmClusterPatchHistoryEntryResult(
        action=pulumi.get(__response__, 'action'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        patch_history_entry_id=pulumi.get(__response__, 'patch_history_entry_id'),
        patch_id=pulumi.get(__response__, 'patch_id'),
        state=pulumi.get(__response__, 'state'),
        time_ended=pulumi.get(__response__, 'time_ended'),
        time_started=pulumi.get(__response__, 'time_started'),
        vm_cluster_id=pulumi.get(__response__, 'vm_cluster_id')))
