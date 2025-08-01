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
    'GetTargetAlertPolicyAssociationResult',
    'AwaitableGetTargetAlertPolicyAssociationResult',
    'get_target_alert_policy_association',
    'get_target_alert_policy_association_output',
]

@pulumi.output_type
class GetTargetAlertPolicyAssociationResult:
    """
    A collection of values returned by getTargetAlertPolicyAssociation.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, is_enabled=None, lifecycle_details=None, policy_id=None, state=None, system_tags=None, target_alert_policy_association_id=None, target_id=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
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
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if policy_id and not isinstance(policy_id, str):
            raise TypeError("Expected argument 'policy_id' to be a str")
        pulumi.set(__self__, "policy_id", policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if target_alert_policy_association_id and not isinstance(target_alert_policy_association_id, str):
            raise TypeError("Expected argument 'target_alert_policy_association_id' to be a str")
        pulumi.set(__self__, "target_alert_policy_association_id", target_alert_policy_association_id)
        if target_id and not isinstance(target_id, str):
            raise TypeError("Expected argument 'target_id' to be a str")
        pulumi.set(__self__, "target_id", target_id)
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
        The OCID of the compartment that contains the policy.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Describes the target-alert policy association.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The display name of the target-alert policy association.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The OCID of the target-alert policy association.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> _builtins.bool:
        """
        Indicates if the target-alert policy association is enabled or disabled by user.
        """
        return pulumi.get(self, "is_enabled")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Details about the current state of the target-alert policy association.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="policyId")
    def policy_id(self) -> _builtins.str:
        """
        The OCID of the alert policy.
        """
        return pulumi.get(self, "policy_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the target-alert policy association.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="targetAlertPolicyAssociationId")
    def target_alert_policy_association_id(self) -> _builtins.str:
        return pulumi.get(self, "target_alert_policy_association_id")

    @_builtins.property
    @pulumi.getter(name="targetId")
    def target_id(self) -> _builtins.str:
        """
        The OCID of the target on which alert policy is to be applied.
        """
        return pulumi.get(self, "target_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        Creation date and time of the alert policy, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        Last date and time the alert policy was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetTargetAlertPolicyAssociationResult(GetTargetAlertPolicyAssociationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetTargetAlertPolicyAssociationResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            is_enabled=self.is_enabled,
            lifecycle_details=self.lifecycle_details,
            policy_id=self.policy_id,
            state=self.state,
            system_tags=self.system_tags,
            target_alert_policy_association_id=self.target_alert_policy_association_id,
            target_id=self.target_id,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_target_alert_policy_association(target_alert_policy_association_id: Optional[_builtins.str] = None,
                                        opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetTargetAlertPolicyAssociationResult:
    """
    This data source provides details about a specific Target Alert Policy Association resource in Oracle Cloud Infrastructure Data Safe service.

    Gets the details of target-alert policy association by its ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_target_alert_policy_association = oci.DataSafe.get_target_alert_policy_association(target_alert_policy_association_id=test_target_alert_policy_association_oci_data_safe_target_alert_policy_association["id"])
    ```


    :param _builtins.str target_alert_policy_association_id: The OCID of the target-alert policy association.
    """
    __args__ = dict()
    __args__['targetAlertPolicyAssociationId'] = target_alert_policy_association_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getTargetAlertPolicyAssociation:getTargetAlertPolicyAssociation', __args__, opts=opts, typ=GetTargetAlertPolicyAssociationResult).value

    return AwaitableGetTargetAlertPolicyAssociationResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        policy_id=pulumi.get(__ret__, 'policy_id'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        target_alert_policy_association_id=pulumi.get(__ret__, 'target_alert_policy_association_id'),
        target_id=pulumi.get(__ret__, 'target_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_target_alert_policy_association_output(target_alert_policy_association_id: Optional[pulumi.Input[_builtins.str]] = None,
                                               opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetTargetAlertPolicyAssociationResult]:
    """
    This data source provides details about a specific Target Alert Policy Association resource in Oracle Cloud Infrastructure Data Safe service.

    Gets the details of target-alert policy association by its ID.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_target_alert_policy_association = oci.DataSafe.get_target_alert_policy_association(target_alert_policy_association_id=test_target_alert_policy_association_oci_data_safe_target_alert_policy_association["id"])
    ```


    :param _builtins.str target_alert_policy_association_id: The OCID of the target-alert policy association.
    """
    __args__ = dict()
    __args__['targetAlertPolicyAssociationId'] = target_alert_policy_association_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getTargetAlertPolicyAssociation:getTargetAlertPolicyAssociation', __args__, opts=opts, typ=GetTargetAlertPolicyAssociationResult)
    return __ret__.apply(lambda __response__: GetTargetAlertPolicyAssociationResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        policy_id=pulumi.get(__response__, 'policy_id'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        target_alert_policy_association_id=pulumi.get(__response__, 'target_alert_policy_association_id'),
        target_id=pulumi.get(__response__, 'target_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
