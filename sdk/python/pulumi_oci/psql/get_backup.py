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
    'GetBackupResult',
    'AwaitableGetBackupResult',
    'get_backup',
    'get_backup_output',
]

@pulumi.output_type
class GetBackupResult:
    """
    A collection of values returned by getBackup.
    """
    def __init__(__self__, backup_id=None, backup_size=None, compartment_id=None, copy_statuses=None, db_system_details=None, db_system_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, last_accepted_request_token=None, last_completed_request_token=None, lifecycle_details=None, retention_period=None, source_backup_details=None, source_type=None, state=None, system_tags=None, time_created=None, time_created_precise=None, time_updated=None):
        if backup_id and not isinstance(backup_id, str):
            raise TypeError("Expected argument 'backup_id' to be a str")
        pulumi.set(__self__, "backup_id", backup_id)
        if backup_size and not isinstance(backup_size, int):
            raise TypeError("Expected argument 'backup_size' to be a int")
        pulumi.set(__self__, "backup_size", backup_size)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if copy_statuses and not isinstance(copy_statuses, list):
            raise TypeError("Expected argument 'copy_statuses' to be a list")
        pulumi.set(__self__, "copy_statuses", copy_statuses)
        if db_system_details and not isinstance(db_system_details, list):
            raise TypeError("Expected argument 'db_system_details' to be a list")
        pulumi.set(__self__, "db_system_details", db_system_details)
        if db_system_id and not isinstance(db_system_id, str):
            raise TypeError("Expected argument 'db_system_id' to be a str")
        pulumi.set(__self__, "db_system_id", db_system_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if last_accepted_request_token and not isinstance(last_accepted_request_token, str):
            raise TypeError("Expected argument 'last_accepted_request_token' to be a str")
        pulumi.set(__self__, "last_accepted_request_token", last_accepted_request_token)
        if last_completed_request_token and not isinstance(last_completed_request_token, str):
            raise TypeError("Expected argument 'last_completed_request_token' to be a str")
        pulumi.set(__self__, "last_completed_request_token", last_completed_request_token)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if retention_period and not isinstance(retention_period, int):
            raise TypeError("Expected argument 'retention_period' to be a int")
        pulumi.set(__self__, "retention_period", retention_period)
        if source_backup_details and not isinstance(source_backup_details, list):
            raise TypeError("Expected argument 'source_backup_details' to be a list")
        pulumi.set(__self__, "source_backup_details", source_backup_details)
        if source_type and not isinstance(source_type, str):
            raise TypeError("Expected argument 'source_type' to be a str")
        pulumi.set(__self__, "source_type", source_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_created_precise and not isinstance(time_created_precise, str):
            raise TypeError("Expected argument 'time_created_precise' to be a str")
        pulumi.set(__self__, "time_created_precise", time_created_precise)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="backupId")
    def backup_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup in the source region
        """
        return pulumi.get(self, "backup_id")

    @_builtins.property
    @pulumi.getter(name="backupSize")
    def backup_size(self) -> _builtins.int:
        """
        The size of the backup, in gigabytes.
        """
        return pulumi.get(self, "backup_size")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the backup.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="copyStatuses")
    def copy_statuses(self) -> Sequence['outputs.GetBackupCopyStatusResult']:
        """
        List of status for Backup Copy
        """
        return pulumi.get(self, "copy_statuses")

    @_builtins.property
    @pulumi.getter(name="dbSystemDetails")
    def db_system_details(self) -> Sequence['outputs.GetBackupDbSystemDetailResult']:
        """
        Information about the database system associated with a backup.
        """
        return pulumi.get(self, "db_system_details")

    @_builtins.property
    @pulumi.getter(name="dbSystemId")
    def db_system_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup's source database system.
        """
        return pulumi.get(self, "db_system_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A description for the backup.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly display name for the backup. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lastAcceptedRequestToken")
    def last_accepted_request_token(self) -> _builtins.str:
        """
        lastAcceptedRequestToken from MP.
        """
        return pulumi.get(self, "last_accepted_request_token")

    @_builtins.property
    @pulumi.getter(name="lastCompletedRequestToken")
    def last_completed_request_token(self) -> _builtins.str:
        """
        lastCompletedRequestToken from MP.
        """
        return pulumi.get(self, "last_completed_request_token")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="retentionPeriod")
    def retention_period(self) -> _builtins.int:
        """
        Backup retention period in days.
        """
        return pulumi.get(self, "retention_period")

    @_builtins.property
    @pulumi.getter(name="sourceBackupDetails")
    def source_backup_details(self) -> Sequence['outputs.GetBackupSourceBackupDetailResult']:
        """
        Information about the Source Backup associated with a backup.
        """
        return pulumi.get(self, "source_backup_details")

    @_builtins.property
    @pulumi.getter(name="sourceType")
    def source_type(self) -> _builtins.str:
        """
        Specifies whether the backup was created manually, taken on schedule defined in the a backup policy, or copied from the remote location.
        """
        return pulumi.get(self, "source_type")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the backup.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the backup request was received, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeCreatedPrecise")
    def time_created_precise(self) -> _builtins.str:
        """
        The date and time the backup was created. This is the time the actual point-in-time data snapshot was taken, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created_precise")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the backup was updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetBackupResult(GetBackupResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetBackupResult(
            backup_id=self.backup_id,
            backup_size=self.backup_size,
            compartment_id=self.compartment_id,
            copy_statuses=self.copy_statuses,
            db_system_details=self.db_system_details,
            db_system_id=self.db_system_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            last_accepted_request_token=self.last_accepted_request_token,
            last_completed_request_token=self.last_completed_request_token,
            lifecycle_details=self.lifecycle_details,
            retention_period=self.retention_period,
            source_backup_details=self.source_backup_details,
            source_type=self.source_type,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_created_precise=self.time_created_precise,
            time_updated=self.time_updated)


def get_backup(backup_id: Optional[_builtins.str] = None,
               opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetBackupResult:
    """
    This data source provides details about a specific Backup resource in Oracle Cloud Infrastructure Psql service.

    Gets a backup by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backup = oci.Psql.get_backup(backup_id=test_backup_oci_psql_backup["id"])
    ```


    :param _builtins.str backup_id: A unique identifier for the backup.
    """
    __args__ = dict()
    __args__['backupId'] = backup_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Psql/getBackup:getBackup', __args__, opts=opts, typ=GetBackupResult).value

    return AwaitableGetBackupResult(
        backup_id=pulumi.get(__ret__, 'backup_id'),
        backup_size=pulumi.get(__ret__, 'backup_size'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        copy_statuses=pulumi.get(__ret__, 'copy_statuses'),
        db_system_details=pulumi.get(__ret__, 'db_system_details'),
        db_system_id=pulumi.get(__ret__, 'db_system_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        last_accepted_request_token=pulumi.get(__ret__, 'last_accepted_request_token'),
        last_completed_request_token=pulumi.get(__ret__, 'last_completed_request_token'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        retention_period=pulumi.get(__ret__, 'retention_period'),
        source_backup_details=pulumi.get(__ret__, 'source_backup_details'),
        source_type=pulumi.get(__ret__, 'source_type'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_created_precise=pulumi.get(__ret__, 'time_created_precise'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_backup_output(backup_id: Optional[pulumi.Input[_builtins.str]] = None,
                      opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetBackupResult]:
    """
    This data source provides details about a specific Backup resource in Oracle Cloud Infrastructure Psql service.

    Gets a backup by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_backup = oci.Psql.get_backup(backup_id=test_backup_oci_psql_backup["id"])
    ```


    :param _builtins.str backup_id: A unique identifier for the backup.
    """
    __args__ = dict()
    __args__['backupId'] = backup_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Psql/getBackup:getBackup', __args__, opts=opts, typ=GetBackupResult)
    return __ret__.apply(lambda __response__: GetBackupResult(
        backup_id=pulumi.get(__response__, 'backup_id'),
        backup_size=pulumi.get(__response__, 'backup_size'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        copy_statuses=pulumi.get(__response__, 'copy_statuses'),
        db_system_details=pulumi.get(__response__, 'db_system_details'),
        db_system_id=pulumi.get(__response__, 'db_system_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        last_accepted_request_token=pulumi.get(__response__, 'last_accepted_request_token'),
        last_completed_request_token=pulumi.get(__response__, 'last_completed_request_token'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        retention_period=pulumi.get(__response__, 'retention_period'),
        source_backup_details=pulumi.get(__response__, 'source_backup_details'),
        source_type=pulumi.get(__response__, 'source_type'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_created_precise=pulumi.get(__response__, 'time_created_precise'),
        time_updated=pulumi.get(__response__, 'time_updated')))
