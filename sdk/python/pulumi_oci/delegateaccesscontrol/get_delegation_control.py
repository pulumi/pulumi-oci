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
    'GetDelegationControlResult',
    'AwaitableGetDelegationControlResult',
    'get_delegation_control',
    'get_delegation_control_output',
]

@pulumi.output_type
class GetDelegationControlResult:
    """
    A collection of values returned by getDelegationControl.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, delegation_control_id=None, delegation_subscription_ids=None, description=None, display_name=None, freeform_tags=None, id=None, is_auto_approve_during_maintenance=None, lifecycle_state_details=None, notification_message_format=None, notification_topic_id=None, num_approvals_required=None, pre_approved_service_provider_action_names=None, resource_ids=None, resource_type=None, state=None, system_tags=None, time_created=None, time_deleted=None, time_updated=None, vault_id=None, vault_key_id=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if delegation_control_id and not isinstance(delegation_control_id, str):
            raise TypeError("Expected argument 'delegation_control_id' to be a str")
        pulumi.set(__self__, "delegation_control_id", delegation_control_id)
        if delegation_subscription_ids and not isinstance(delegation_subscription_ids, list):
            raise TypeError("Expected argument 'delegation_subscription_ids' to be a list")
        pulumi.set(__self__, "delegation_subscription_ids", delegation_subscription_ids)
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
        if is_auto_approve_during_maintenance and not isinstance(is_auto_approve_during_maintenance, bool):
            raise TypeError("Expected argument 'is_auto_approve_during_maintenance' to be a bool")
        pulumi.set(__self__, "is_auto_approve_during_maintenance", is_auto_approve_during_maintenance)
        if lifecycle_state_details and not isinstance(lifecycle_state_details, str):
            raise TypeError("Expected argument 'lifecycle_state_details' to be a str")
        pulumi.set(__self__, "lifecycle_state_details", lifecycle_state_details)
        if notification_message_format and not isinstance(notification_message_format, str):
            raise TypeError("Expected argument 'notification_message_format' to be a str")
        pulumi.set(__self__, "notification_message_format", notification_message_format)
        if notification_topic_id and not isinstance(notification_topic_id, str):
            raise TypeError("Expected argument 'notification_topic_id' to be a str")
        pulumi.set(__self__, "notification_topic_id", notification_topic_id)
        if num_approvals_required and not isinstance(num_approvals_required, int):
            raise TypeError("Expected argument 'num_approvals_required' to be a int")
        pulumi.set(__self__, "num_approvals_required", num_approvals_required)
        if pre_approved_service_provider_action_names and not isinstance(pre_approved_service_provider_action_names, list):
            raise TypeError("Expected argument 'pre_approved_service_provider_action_names' to be a list")
        pulumi.set(__self__, "pre_approved_service_provider_action_names", pre_approved_service_provider_action_names)
        if resource_ids and not isinstance(resource_ids, list):
            raise TypeError("Expected argument 'resource_ids' to be a list")
        pulumi.set(__self__, "resource_ids", resource_ids)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_deleted and not isinstance(time_deleted, str):
            raise TypeError("Expected argument 'time_deleted' to be a str")
        pulumi.set(__self__, "time_deleted", time_deleted)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if vault_id and not isinstance(vault_id, str):
            raise TypeError("Expected argument 'vault_id' to be a str")
        pulumi.set(__self__, "vault_id", vault_id)
        if vault_key_id and not isinstance(vault_key_id, str):
            raise TypeError("Expected argument 'vault_key_id' to be a str")
        pulumi.set(__self__, "vault_key_id", vault_key_id)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the Delegation Control.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="delegationControlId")
    def delegation_control_id(self) -> _builtins.str:
        return pulumi.get(self, "delegation_control_id")

    @_builtins.property
    @pulumi.getter(name="delegationSubscriptionIds")
    def delegation_subscription_ids(self) -> Sequence[_builtins.str]:
        """
        List of Delegation Subscription OCID that are allowed for this Delegation Control. The allowed subscriptions will determine the available Service Provider Actions. Only support operators for the allowed subscriptions are allowed to create Delegated Resource Access Request.
        """
        return pulumi.get(self, "delegation_subscription_ids")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Description of the Delegation Control.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Name of the Delegation Control. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the Delegation Control.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isAutoApproveDuringMaintenance")
    def is_auto_approve_during_maintenance(self) -> _builtins.bool:
        """
        Set to true to allow all Delegated Resource Access Request to be approved automatically during maintenance.
        """
        return pulumi.get(self, "is_auto_approve_during_maintenance")

    @_builtins.property
    @pulumi.getter(name="lifecycleStateDetails")
    def lifecycle_state_details(self) -> _builtins.str:
        """
        Description of the current lifecycle state in more detail.
        """
        return pulumi.get(self, "lifecycle_state_details")

    @_builtins.property
    @pulumi.getter(name="notificationMessageFormat")
    def notification_message_format(self) -> _builtins.str:
        """
        The format of the Oracle Cloud Infrastructure Notification messages for this Delegation Control.
        """
        return pulumi.get(self, "notification_message_format")

    @_builtins.property
    @pulumi.getter(name="notificationTopicId")
    def notification_topic_id(self) -> _builtins.str:
        """
        The OCID of the Oracle Cloud Infrastructure Notification topic to publish messages related to this Delegation Control.
        """
        return pulumi.get(self, "notification_topic_id")

    @_builtins.property
    @pulumi.getter(name="numApprovalsRequired")
    def num_approvals_required(self) -> _builtins.int:
        """
        number of approvals required.
        """
        return pulumi.get(self, "num_approvals_required")

    @_builtins.property
    @pulumi.getter(name="preApprovedServiceProviderActionNames")
    def pre_approved_service_provider_action_names(self) -> Sequence[_builtins.str]:
        """
        List of pre-approved Service Provider Action names. The list of pre-defined Service Provider Actions can be obtained from the ListServiceProviderActions API. Delegated Resource Access Requests associated with a resource governed by this Delegation Control will be automatically approved if the Delegated Resource Access Request only contain Service Provider Actions in the pre-approved list.
        """
        return pulumi.get(self, "pre_approved_service_provider_action_names")

    @_builtins.property
    @pulumi.getter(name="resourceIds")
    def resource_ids(self) -> Sequence[_builtins.str]:
        """
        The OCID of the selected resources that this Delegation Control is applicable to.
        """
        return pulumi.get(self, "resource_ids")

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> _builtins.str:
        """
        Resource type for which the Delegation Control is applicable to.
        """
        return pulumi.get(self, "resource_type")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current lifecycle state of the Delegation Control.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Time when the Delegation Control was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeDeleted")
    def time_deleted(self) -> _builtins.str:
        """
        Time when the Delegation Control was deleted expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format, e.g. '2020-05-22T21:10:29.600Z'. Note a deleted Delegation Control still stays in the system, so that you can still audit Service Provider Actions associated with Delegated Resource Access Requests raised on target resources governed by the deleted Delegation Control.
        """
        return pulumi.get(self, "time_deleted")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Time when the Delegation Control was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
        """
        return pulumi.get(self, "time_updated")

    @_builtins.property
    @pulumi.getter(name="vaultId")
    def vault_id(self) -> _builtins.str:
        """
        The OCID of the Oracle Cloud Infrastructure Vault that will store the secrets containing the SSH keys to access the resource governed by this Delegation Control by Delegate Access Control Service. This property is required when resourceType is CLOUDVMCLUSTER. Delegate Access Control Service will generate the SSH keys and store them as secrets in the Oracle Cloud Infrastructure Vault.
        """
        return pulumi.get(self, "vault_id")

    @_builtins.property
    @pulumi.getter(name="vaultKeyId")
    def vault_key_id(self) -> _builtins.str:
        """
        The OCID of the Master Encryption Key in the Oracle Cloud Infrastructure Vault specified by vaultId. This key will be used to encrypt the SSH keys to access the resource governed by this Delegation Control by Delegate Access Control Service. This property is required when resourceType is CLOUDVMCLUSTER.
        """
        return pulumi.get(self, "vault_key_id")


class AwaitableGetDelegationControlResult(GetDelegationControlResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDelegationControlResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            delegation_control_id=self.delegation_control_id,
            delegation_subscription_ids=self.delegation_subscription_ids,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_auto_approve_during_maintenance=self.is_auto_approve_during_maintenance,
            lifecycle_state_details=self.lifecycle_state_details,
            notification_message_format=self.notification_message_format,
            notification_topic_id=self.notification_topic_id,
            num_approvals_required=self.num_approvals_required,
            pre_approved_service_provider_action_names=self.pre_approved_service_provider_action_names,
            resource_ids=self.resource_ids,
            resource_type=self.resource_type,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_deleted=self.time_deleted,
            time_updated=self.time_updated,
            vault_id=self.vault_id,
            vault_key_id=self.vault_key_id)


def get_delegation_control(delegation_control_id: Optional[_builtins.str] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDelegationControlResult:
    """
    This data source provides details about a specific Delegation Control resource in Oracle Cloud Infrastructure Delegate Access Control service.

    Gets the Delegation Control associated with the specified Delegation Control ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_delegation_control = oci.DelegateAccessControl.get_delegation_control(delegation_control_id=test_delegation_control_oci_delegate_access_control_delegation_control["id"])
    ```


    :param _builtins.str delegation_control_id: unique Delegation Control identifier
    """
    __args__ = dict()
    __args__['delegationControlId'] = delegation_control_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DelegateAccessControl/getDelegationControl:getDelegationControl', __args__, opts=opts, typ=GetDelegationControlResult).value

    return AwaitableGetDelegationControlResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        delegation_control_id=pulumi.get(__ret__, 'delegation_control_id'),
        delegation_subscription_ids=pulumi.get(__ret__, 'delegation_subscription_ids'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_auto_approve_during_maintenance=pulumi.get(__ret__, 'is_auto_approve_during_maintenance'),
        lifecycle_state_details=pulumi.get(__ret__, 'lifecycle_state_details'),
        notification_message_format=pulumi.get(__ret__, 'notification_message_format'),
        notification_topic_id=pulumi.get(__ret__, 'notification_topic_id'),
        num_approvals_required=pulumi.get(__ret__, 'num_approvals_required'),
        pre_approved_service_provider_action_names=pulumi.get(__ret__, 'pre_approved_service_provider_action_names'),
        resource_ids=pulumi.get(__ret__, 'resource_ids'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_deleted=pulumi.get(__ret__, 'time_deleted'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        vault_id=pulumi.get(__ret__, 'vault_id'),
        vault_key_id=pulumi.get(__ret__, 'vault_key_id'))
def get_delegation_control_output(delegation_control_id: Optional[pulumi.Input[_builtins.str]] = None,
                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDelegationControlResult]:
    """
    This data source provides details about a specific Delegation Control resource in Oracle Cloud Infrastructure Delegate Access Control service.

    Gets the Delegation Control associated with the specified Delegation Control ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_delegation_control = oci.DelegateAccessControl.get_delegation_control(delegation_control_id=test_delegation_control_oci_delegate_access_control_delegation_control["id"])
    ```


    :param _builtins.str delegation_control_id: unique Delegation Control identifier
    """
    __args__ = dict()
    __args__['delegationControlId'] = delegation_control_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DelegateAccessControl/getDelegationControl:getDelegationControl', __args__, opts=opts, typ=GetDelegationControlResult)
    return __ret__.apply(lambda __response__: GetDelegationControlResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        delegation_control_id=pulumi.get(__response__, 'delegation_control_id'),
        delegation_subscription_ids=pulumi.get(__response__, 'delegation_subscription_ids'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_auto_approve_during_maintenance=pulumi.get(__response__, 'is_auto_approve_during_maintenance'),
        lifecycle_state_details=pulumi.get(__response__, 'lifecycle_state_details'),
        notification_message_format=pulumi.get(__response__, 'notification_message_format'),
        notification_topic_id=pulumi.get(__response__, 'notification_topic_id'),
        num_approvals_required=pulumi.get(__response__, 'num_approvals_required'),
        pre_approved_service_provider_action_names=pulumi.get(__response__, 'pre_approved_service_provider_action_names'),
        resource_ids=pulumi.get(__response__, 'resource_ids'),
        resource_type=pulumi.get(__response__, 'resource_type'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_deleted=pulumi.get(__response__, 'time_deleted'),
        time_updated=pulumi.get(__response__, 'time_updated'),
        vault_id=pulumi.get(__response__, 'vault_id'),
        vault_key_id=pulumi.get(__response__, 'vault_key_id')))
