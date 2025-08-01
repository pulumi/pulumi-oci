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
    'GetSnapshotsResult',
    'AwaitableGetSnapshotsResult',
    'get_snapshots',
    'get_snapshots_output',
]

@pulumi.output_type
class GetSnapshotsResult:
    """
    A collection of values returned by getSnapshots.
    """
    def __init__(__self__, compartment_id=None, file_system_id=None, filesystem_snapshot_policy_id=None, filters=None, id=None, snapshots=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if file_system_id and not isinstance(file_system_id, str):
            raise TypeError("Expected argument 'file_system_id' to be a str")
        pulumi.set(__self__, "file_system_id", file_system_id)
        if filesystem_snapshot_policy_id and not isinstance(filesystem_snapshot_policy_id, str):
            raise TypeError("Expected argument 'filesystem_snapshot_policy_id' to be a str")
        pulumi.set(__self__, "filesystem_snapshot_policy_id", filesystem_snapshot_policy_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if snapshots and not isinstance(snapshots, list):
            raise TypeError("Expected argument 'snapshots' to be a list")
        pulumi.set(__self__, "snapshots", snapshots)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="fileSystemId")
    def file_system_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system from which the snapshot was created.
        """
        return pulumi.get(self, "file_system_id")

    @_builtins.property
    @pulumi.getter(name="filesystemSnapshotPolicyId")
    def filesystem_snapshot_policy_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy that created this snapshot.
        """
        return pulumi.get(self, "filesystem_snapshot_policy_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSnapshotsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def snapshots(self) -> Sequence['outputs.GetSnapshotsSnapshotResult']:
        """
        The list of snapshots.
        """
        return pulumi.get(self, "snapshots")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the snapshot.
        """
        return pulumi.get(self, "state")


class AwaitableGetSnapshotsResult(GetSnapshotsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSnapshotsResult(
            compartment_id=self.compartment_id,
            file_system_id=self.file_system_id,
            filesystem_snapshot_policy_id=self.filesystem_snapshot_policy_id,
            filters=self.filters,
            id=self.id,
            snapshots=self.snapshots,
            state=self.state)


def get_snapshots(compartment_id: Optional[_builtins.str] = None,
                  file_system_id: Optional[_builtins.str] = None,
                  filesystem_snapshot_policy_id: Optional[_builtins.str] = None,
                  filters: Optional[Sequence[Union['GetSnapshotsFilterArgs', 'GetSnapshotsFilterArgsDict']]] = None,
                  id: Optional[_builtins.str] = None,
                  state: Optional[_builtins.str] = None,
                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSnapshotsResult:
    """
    This data source provides the list of Snapshots in Oracle Cloud Infrastructure File Storage service.

    Lists snapshots of the specified file system, or by file system snapshot policy and compartment,
    or by file system snapshot policy and file system.

    If file system ID is not specified, a file system snapshot policy ID and compartment ID must be specified.

    Users can only sort by time created when listing snapshots by file system snapshot policy ID and compartment ID
    (sort by name is NOT supported for listing snapshots by policy and compartment).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_snapshots = oci.FileStorage.get_snapshots(compartment_id=compartment_id,
        file_system_id=test_file_system["id"],
        filesystem_snapshot_policy_id=test_filesystem_snapshot_policy["id"],
        id=snapshot_id,
        state=snapshot_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str file_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
    :param _builtins.str filesystem_snapshot_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy that is used to create the snapshots.
    :param _builtins.str id: Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
    :param _builtins.str state: Filter results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['fileSystemId'] = file_system_id
    __args__['filesystemSnapshotPolicyId'] = filesystem_snapshot_policy_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FileStorage/getSnapshots:getSnapshots', __args__, opts=opts, typ=GetSnapshotsResult).value

    return AwaitableGetSnapshotsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        file_system_id=pulumi.get(__ret__, 'file_system_id'),
        filesystem_snapshot_policy_id=pulumi.get(__ret__, 'filesystem_snapshot_policy_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        snapshots=pulumi.get(__ret__, 'snapshots'),
        state=pulumi.get(__ret__, 'state'))
def get_snapshots_output(compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         file_system_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         filesystem_snapshot_policy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSnapshotsFilterArgs', 'GetSnapshotsFilterArgsDict']]]]] = None,
                         id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                         opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSnapshotsResult]:
    """
    This data source provides the list of Snapshots in Oracle Cloud Infrastructure File Storage service.

    Lists snapshots of the specified file system, or by file system snapshot policy and compartment,
    or by file system snapshot policy and file system.

    If file system ID is not specified, a file system snapshot policy ID and compartment ID must be specified.

    Users can only sort by time created when listing snapshots by file system snapshot policy ID and compartment ID
    (sort by name is NOT supported for listing snapshots by policy and compartment).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_snapshots = oci.FileStorage.get_snapshots(compartment_id=compartment_id,
        file_system_id=test_file_system["id"],
        filesystem_snapshot_policy_id=test_filesystem_snapshot_policy["id"],
        id=snapshot_id,
        state=snapshot_state)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str file_system_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
    :param _builtins.str filesystem_snapshot_policy_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system snapshot policy that is used to create the snapshots.
    :param _builtins.str id: Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
    :param _builtins.str state: Filter results by the specified lifecycle state. Must be a valid state for the resource type.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['fileSystemId'] = file_system_id
    __args__['filesystemSnapshotPolicyId'] = filesystem_snapshot_policy_id
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:FileStorage/getSnapshots:getSnapshots', __args__, opts=opts, typ=GetSnapshotsResult)
    return __ret__.apply(lambda __response__: GetSnapshotsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        file_system_id=pulumi.get(__response__, 'file_system_id'),
        filesystem_snapshot_policy_id=pulumi.get(__response__, 'filesystem_snapshot_policy_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        snapshots=pulumi.get(__response__, 'snapshots'),
        state=pulumi.get(__response__, 'state')))
