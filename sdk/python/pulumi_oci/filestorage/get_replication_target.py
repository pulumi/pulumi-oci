# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetReplicationTargetResult',
    'AwaitableGetReplicationTargetResult',
    'get_replication_target',
    'get_replication_target_output',
]

@pulumi.output_type
class GetReplicationTargetResult:
    """
    A collection of values returned by getReplicationTarget.
    """
    def __init__(__self__, availability_domain=None, compartment_id=None, defined_tags=None, delta_progress=None, delta_status=None, display_name=None, freeform_tags=None, id=None, last_snapshot_id=None, lifecycle_details=None, recovery_point_time=None, replication_id=None, replication_target_id=None, source_id=None, state=None, target_id=None, time_created=None):
        if availability_domain and not isinstance(availability_domain, str):
            raise TypeError("Expected argument 'availability_domain' to be a str")
        pulumi.set(__self__, "availability_domain", availability_domain)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if delta_progress and not isinstance(delta_progress, str):
            raise TypeError("Expected argument 'delta_progress' to be a str")
        pulumi.set(__self__, "delta_progress", delta_progress)
        if delta_status and not isinstance(delta_status, str):
            raise TypeError("Expected argument 'delta_status' to be a str")
        pulumi.set(__self__, "delta_status", delta_status)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if last_snapshot_id and not isinstance(last_snapshot_id, str):
            raise TypeError("Expected argument 'last_snapshot_id' to be a str")
        pulumi.set(__self__, "last_snapshot_id", last_snapshot_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if recovery_point_time and not isinstance(recovery_point_time, str):
            raise TypeError("Expected argument 'recovery_point_time' to be a str")
        pulumi.set(__self__, "recovery_point_time", recovery_point_time)
        if replication_id and not isinstance(replication_id, str):
            raise TypeError("Expected argument 'replication_id' to be a str")
        pulumi.set(__self__, "replication_id", replication_id)
        if replication_target_id and not isinstance(replication_target_id, str):
            raise TypeError("Expected argument 'replication_target_id' to be a str")
        pulumi.set(__self__, "replication_target_id", replication_target_id)
        if source_id and not isinstance(source_id, str):
            raise TypeError("Expected argument 'source_id' to be a str")
        pulumi.set(__self__, "source_id", source_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)

    @property
    @pulumi.getter(name="availabilityDomain")
    def availability_domain(self) -> str:
        """
        The availability domain the replication target is in. Must be in the same availability domain as the target file system. Example: `Uocm:PHX-AD-1`
        """
        return pulumi.get(self, "availability_domain")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the replication.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="deltaProgress")
    def delta_progress(self) -> str:
        """
        Percentage progress of the current replication cycle.
        """
        return pulumi.get(self, "delta_progress")

    @property
    @pulumi.getter(name="deltaStatus")
    def delta_status(self) -> str:
        """
        The current state of the snapshot during replication operations.
        """
        return pulumi.get(self, "delta_status")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. This name is same as the replication display name for the associated resource. Example: `My Replication`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="lastSnapshotId")
    def last_snapshot_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last snapshot snapshot which was completely applied to the target file system. Empty while the initial snapshot is being applied.
        """
        return pulumi.get(self, "last_snapshot_id")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Additional information about the current `lifecycleState`.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="recoveryPointTime")
    def recovery_point_time(self) -> str:
        """
        The snapshotTime of the most recent recoverable replication snapshot in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-04-04T20:01:29.100Z`
        """
        return pulumi.get(self, "recovery_point_time")

    @property
    @pulumi.getter(name="replicationId")
    def replication_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of replication.
        """
        return pulumi.get(self, "replication_id")

    @property
    @pulumi.getter(name="replicationTargetId")
    def replication_target_id(self) -> str:
        return pulumi.get(self, "replication_target_id")

    @property
    @pulumi.getter(name="sourceId")
    def source_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of source filesystem.
        """
        return pulumi.get(self, "source_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of this replication.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="targetId")
    def target_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of target filesystem.
        """
        return pulumi.get(self, "target_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time the replication target was created in target region. in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format. Example: `2021-01-04T20:01:29.100Z`
        """
        return pulumi.get(self, "time_created")


class AwaitableGetReplicationTargetResult(GetReplicationTargetResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetReplicationTargetResult(
            availability_domain=self.availability_domain,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            delta_progress=self.delta_progress,
            delta_status=self.delta_status,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            last_snapshot_id=self.last_snapshot_id,
            lifecycle_details=self.lifecycle_details,
            recovery_point_time=self.recovery_point_time,
            replication_id=self.replication_id,
            replication_target_id=self.replication_target_id,
            source_id=self.source_id,
            state=self.state,
            target_id=self.target_id,
            time_created=self.time_created)


def get_replication_target(replication_target_id: Optional[str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetReplicationTargetResult:
    """
    This data source provides details about a specific Replication Target resource in Oracle Cloud Infrastructure File Storage service.

    Gets the specified replication target's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_replication_target = oci.FileStorage.get_replication_target(replication_target_id=oci_file_storage_replication_target["test_replication_target"]["id"])
    ```


    :param str replication_target_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication target.
    """
    __args__ = dict()
    __args__['replicationTargetId'] = replication_target_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:FileStorage/getReplicationTarget:getReplicationTarget', __args__, opts=opts, typ=GetReplicationTargetResult).value

    return AwaitableGetReplicationTargetResult(
        availability_domain=__ret__.availability_domain,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        delta_progress=__ret__.delta_progress,
        delta_status=__ret__.delta_status,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        last_snapshot_id=__ret__.last_snapshot_id,
        lifecycle_details=__ret__.lifecycle_details,
        recovery_point_time=__ret__.recovery_point_time,
        replication_id=__ret__.replication_id,
        replication_target_id=__ret__.replication_target_id,
        source_id=__ret__.source_id,
        state=__ret__.state,
        target_id=__ret__.target_id,
        time_created=__ret__.time_created)


@_utilities.lift_output_func(get_replication_target)
def get_replication_target_output(replication_target_id: Optional[pulumi.Input[str]] = None,
                                  opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetReplicationTargetResult]:
    """
    This data source provides details about a specific Replication Target resource in Oracle Cloud Infrastructure File Storage service.

    Gets the specified replication target's information.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_replication_target = oci.FileStorage.get_replication_target(replication_target_id=oci_file_storage_replication_target["test_replication_target"]["id"])
    ```


    :param str replication_target_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the replication target.
    """
    ...