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
    'GetProtectionPolicyResult',
    'AwaitableGetProtectionPolicyResult',
    'get_protection_policy',
    'get_protection_policy_output',
]

@pulumi.output_type
class GetProtectionPolicyResult:
    """
    A collection of values returned by getProtectionPolicy.
    """
    def __init__(__self__, backup_retention_period_in_days=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, is_predefined_policy=None, lifecycle_details=None, protection_policy_id=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if backup_retention_period_in_days and not isinstance(backup_retention_period_in_days, int):
            raise TypeError("Expected argument 'backup_retention_period_in_days' to be a int")
        pulumi.set(__self__, "backup_retention_period_in_days", backup_retention_period_in_days)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if is_predefined_policy and not isinstance(is_predefined_policy, bool):
            raise TypeError("Expected argument 'is_predefined_policy' to be a bool")
        pulumi.set(__self__, "is_predefined_policy", is_predefined_policy)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if protection_policy_id and not isinstance(protection_policy_id, str):
            raise TypeError("Expected argument 'protection_policy_id' to be a str")
        pulumi.set(__self__, "protection_policy_id", protection_policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @property
    @pulumi.getter(name="backupRetentionPeriodInDays")
    def backup_retention_period_in_days(self) -> int:
        """
        The maximum number of days to retain backups for a protected database. Specify a period ranging from a minimum 14 days to a maximum 95 days. For example, specify the value 55 if you want to retain backups for 55 days.
        """
        return pulumi.get(self, "backup_retention_period_in_days")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that contains the protection policy.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user provided name for the protection policy.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The protection policy OCID.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="isPredefinedPolicy")
    def is_predefined_policy(self) -> bool:
        """
        Set to TRUE if the policy is Oracle-defined, and FALSE for a user-defined custom policy. You can modify only the custom policies.
        """
        return pulumi.get(self, "is_predefined_policy")

    @property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> str:
        """
        Detailed description about the current lifecycle state of the protection policy. For example, it can be used to provide actionable information for a resource in a Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @property
    @pulumi.getter(name="protectionPolicyId")
    def protection_policy_id(self) -> str:
        return pulumi.get(self, "protection_policy_id")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the protection policy. Allowed values are:
        * CREATING
        * UPDATING
        * ACTIVE
        * DELETING
        * DELETED
        * FAILED
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`. For more information, see [Resource Tags](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/resourcetags.htm)
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        An RFC3339 formatted datetime string that indicates the created time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        An RFC3339 formatted datetime string that indicates the updated time for the protection policy. For example: '2020-05-22T21:10:29.600Z'.
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetProtectionPolicyResult(GetProtectionPolicyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetProtectionPolicyResult(
            backup_retention_period_in_days=self.backup_retention_period_in_days,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_predefined_policy=self.is_predefined_policy,
            lifecycle_details=self.lifecycle_details,
            protection_policy_id=self.protection_policy_id,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_protection_policy(protection_policy_id: Optional[str] = None,
                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetProtectionPolicyResult:
    """
    This data source provides details about a specific Protection Policy resource in Oracle Cloud Infrastructure Recovery service.

    Gets information about a specified protection policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_policy = oci.RecoveryMod.get_protection_policy(protection_policy_id=oci_recovery_protection_policy["test_protection_policy"]["id"])
    ```


    :param str protection_policy_id: The protection policy OCID.
    """
    __args__ = dict()
    __args__['protectionPolicyId'] = protection_policy_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:RecoveryMod/getProtectionPolicy:getProtectionPolicy', __args__, opts=opts, typ=GetProtectionPolicyResult).value

    return AwaitableGetProtectionPolicyResult(
        backup_retention_period_in_days=__ret__.backup_retention_period_in_days,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        is_predefined_policy=__ret__.is_predefined_policy,
        lifecycle_details=__ret__.lifecycle_details,
        protection_policy_id=__ret__.protection_policy_id,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated)


@_utilities.lift_output_func(get_protection_policy)
def get_protection_policy_output(protection_policy_id: Optional[pulumi.Input[str]] = None,
                                 opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetProtectionPolicyResult]:
    """
    This data source provides details about a specific Protection Policy resource in Oracle Cloud Infrastructure Recovery service.

    Gets information about a specified protection policy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_protection_policy = oci.RecoveryMod.get_protection_policy(protection_policy_id=oci_recovery_protection_policy["test_protection_policy"]["id"])
    ```


    :param str protection_policy_id: The protection policy OCID.
    """
    ...