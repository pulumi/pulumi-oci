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

__all__ = ['BackupCancelManagementArgs', 'BackupCancelManagement']

@pulumi.input_type
class BackupCancelManagementArgs:
    def __init__(__self__, *,
                 backup_id: pulumi.Input[_builtins.str],
                 cancel_backup_trigger: Optional[pulumi.Input[_builtins.int]] = None):
        """
        The set of arguments for constructing a BackupCancelManagement resource.
        :param pulumi.Input[_builtins.str] backup_id: The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.int] cancel_backup_trigger: When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        pulumi.set(__self__, "backup_id", backup_id)
        if cancel_backup_trigger is not None:
            pulumi.set(__self__, "cancel_backup_trigger", cancel_backup_trigger)

    @_builtins.property
    @pulumi.getter(name="backupId")
    def backup_id(self) -> pulumi.Input[_builtins.str]:
        """
        The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "backup_id")

    @backup_id.setter
    def backup_id(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "backup_id", value)

    @_builtins.property
    @pulumi.getter(name="cancelBackupTrigger")
    def cancel_backup_trigger(self) -> Optional[pulumi.Input[_builtins.int]]:
        """
        When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "cancel_backup_trigger")

    @cancel_backup_trigger.setter
    def cancel_backup_trigger(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "cancel_backup_trigger", value)


@pulumi.input_type
class _BackupCancelManagementState:
    def __init__(__self__, *,
                 backup_id: Optional[pulumi.Input[_builtins.str]] = None,
                 cancel_backup_trigger: Optional[pulumi.Input[_builtins.int]] = None):
        """
        Input properties used for looking up and filtering BackupCancelManagement resources.
        :param pulumi.Input[_builtins.str] backup_id: The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.int] cancel_backup_trigger: When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if backup_id is not None:
            pulumi.set(__self__, "backup_id", backup_id)
        if cancel_backup_trigger is not None:
            pulumi.set(__self__, "cancel_backup_trigger", cancel_backup_trigger)

    @_builtins.property
    @pulumi.getter(name="backupId")
    def backup_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "backup_id")

    @backup_id.setter
    def backup_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "backup_id", value)

    @_builtins.property
    @pulumi.getter(name="cancelBackupTrigger")
    def cancel_backup_trigger(self) -> Optional[pulumi.Input[_builtins.int]]:
        """
        When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "cancel_backup_trigger")

    @cancel_backup_trigger.setter
    def cancel_backup_trigger(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "cancel_backup_trigger", value)


@pulumi.type_token("oci:Database/backupCancelManagement:BackupCancelManagement")
class BackupCancelManagement(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 backup_id: Optional[pulumi.Input[_builtins.str]] = None,
                 cancel_backup_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 __props__=None):
        """
        This resource provides the Backup Cancel Management resource in Oracle Cloud Infrastructure Database service.

        Cancel automatic full/incremental create backup workrequests specified by the backup Id. This cannot be used on manual backups.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_backup_cancel_management = oci.database.BackupCancelManagement("test_backup_cancel_management",
            backup_id=test_backup["id"],
            cancel_backup_trigger=1)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] backup_id: The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.int] cancel_backup_trigger: When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: BackupCancelManagementArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Backup Cancel Management resource in Oracle Cloud Infrastructure Database service.

        Cancel automatic full/incremental create backup workrequests specified by the backup Id. This cannot be used on manual backups.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_backup_cancel_management = oci.database.BackupCancelManagement("test_backup_cancel_management",
            backup_id=test_backup["id"],
            cancel_backup_trigger=1)
        ```

        ## Import

        Import is not supported for this resource.

        :param str resource_name: The name of the resource.
        :param BackupCancelManagementArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(BackupCancelManagementArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 backup_id: Optional[pulumi.Input[_builtins.str]] = None,
                 cancel_backup_trigger: Optional[pulumi.Input[_builtins.int]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = BackupCancelManagementArgs.__new__(BackupCancelManagementArgs)

            if backup_id is None and not opts.urn:
                raise TypeError("Missing required property 'backup_id'")
            __props__.__dict__["backup_id"] = backup_id
            __props__.__dict__["cancel_backup_trigger"] = cancel_backup_trigger
        super(BackupCancelManagement, __self__).__init__(
            'oci:Database/backupCancelManagement:BackupCancelManagement',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            backup_id: Optional[pulumi.Input[_builtins.str]] = None,
            cancel_backup_trigger: Optional[pulumi.Input[_builtins.int]] = None) -> 'BackupCancelManagement':
        """
        Get an existing BackupCancelManagement resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] backup_id: The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        :param pulumi.Input[_builtins.int] cancel_backup_trigger: When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _BackupCancelManagementState.__new__(_BackupCancelManagementState)

        __props__.__dict__["backup_id"] = backup_id
        __props__.__dict__["cancel_backup_trigger"] = cancel_backup_trigger
        return BackupCancelManagement(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="backupId")
    def backup_id(self) -> pulumi.Output[_builtins.str]:
        """
        The backup [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "backup_id")

    @_builtins.property
    @pulumi.getter(name="cancelBackupTrigger")
    def cancel_backup_trigger(self) -> pulumi.Output[Optional[_builtins.int]]:
        """
        When changed to a different integer, re-triggers cancel backup on the backup specified by the backup_id


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "cancel_backup_trigger")

