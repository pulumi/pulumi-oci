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
    'GetApiaccesscontrolPrivilegedApiControlResult',
    'AwaitableGetApiaccesscontrolPrivilegedApiControlResult',
    'get_apiaccesscontrol_privileged_api_control',
    'get_apiaccesscontrol_privileged_api_control_output',
]

@pulumi.output_type
class GetApiaccesscontrolPrivilegedApiControlResult:
    """
    A collection of values returned by getApiaccesscontrolPrivilegedApiControl.
    """
    def __init__(__self__, approver_group_id_lists=None, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, lifecycle_details=None, notification_topic_id=None, number_of_approvers=None, privileged_api_control_id=None, privileged_operation_lists=None, resource_type=None, resources=None, state=None, state_details=None, system_tags=None, time_created=None, time_deleted=None, time_updated=None):
        if approver_group_id_lists and not isinstance(approver_group_id_lists, list):
            raise TypeError("Expected argument 'approver_group_id_lists' to be a list")
        pulumi.set(__self__, "approver_group_id_lists", approver_group_id_lists)
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
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if notification_topic_id and not isinstance(notification_topic_id, str):
            raise TypeError("Expected argument 'notification_topic_id' to be a str")
        pulumi.set(__self__, "notification_topic_id", notification_topic_id)
        if number_of_approvers and not isinstance(number_of_approvers, int):
            raise TypeError("Expected argument 'number_of_approvers' to be a int")
        pulumi.set(__self__, "number_of_approvers", number_of_approvers)
        if privileged_api_control_id and not isinstance(privileged_api_control_id, str):
            raise TypeError("Expected argument 'privileged_api_control_id' to be a str")
        pulumi.set(__self__, "privileged_api_control_id", privileged_api_control_id)
        if privileged_operation_lists and not isinstance(privileged_operation_lists, list):
            raise TypeError("Expected argument 'privileged_operation_lists' to be a list")
        pulumi.set(__self__, "privileged_operation_lists", privileged_operation_lists)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if resources and not isinstance(resources, list):
            raise TypeError("Expected argument 'resources' to be a list")
        pulumi.set(__self__, "resources", resources)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if state_details and not isinstance(state_details, str):
            raise TypeError("Expected argument 'state_details' to be a str")
        pulumi.set(__self__, "state_details", state_details)
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

    @_builtins.property
    @pulumi.getter(name="approverGroupIdLists")
    def approver_group_id_lists(self) -> Sequence[_builtins.str]:
        """
        List of IAM user group ids who can approve an privilegedApi request associated with a target resource under the governance of this operator control.
        """
        return pulumi.get(self, "approver_group_id_lists")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        Description of privilegedApi control.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        Name of the privilegedApi control. The name must be unique.
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
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiControl.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message that describes the current state of the PrivilegedApiControl in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="notificationTopicId")
    def notification_topic_id(self) -> _builtins.str:
        """
        The OCID of the Oracle Cloud Infrastructure Notification topic to publish messages related to this Privileged Api Control.
        """
        return pulumi.get(self, "notification_topic_id")

    @_builtins.property
    @pulumi.getter(name="numberOfApprovers")
    def number_of_approvers(self) -> _builtins.int:
        """
        Number of approvers required to approve an privilegedApi request.
        """
        return pulumi.get(self, "number_of_approvers")

    @_builtins.property
    @pulumi.getter(name="privilegedApiControlId")
    def privileged_api_control_id(self) -> _builtins.str:
        return pulumi.get(self, "privileged_api_control_id")

    @_builtins.property
    @pulumi.getter(name="privilegedOperationLists")
    def privileged_operation_lists(self) -> Sequence['outputs.GetApiaccesscontrolPrivilegedApiControlPrivilegedOperationListResult']:
        """
        List of privileged operations/apis. These operations/apis will be treaated as secured, once enabled by the Privileged API Managment for a resource. Any of these operations, if needs to be executed, needs to be raised as a PrivilegedApi Request which needs to be approved by customers or it can be pre-approved.
        """
        return pulumi.get(self, "privileged_operation_lists")

    @_builtins.property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> _builtins.str:
        """
        resourceType for which the PrivilegedApiControl is applicable
        """
        return pulumi.get(self, "resource_type")

    @_builtins.property
    @pulumi.getter
    def resources(self) -> Sequence[_builtins.str]:
        """
        contains Resource details
        """
        return pulumi.get(self, "resources")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the PrivilegedApiControl.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="stateDetails")
    def state_details(self) -> _builtins.str:
        """
        A message that describes the current state of the PrivilegedApiControl in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        """
        return pulumi.get(self, "state_details")

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
        The date and time the PrivilegedApiControl was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeDeleted")
    def time_deleted(self) -> _builtins.str:
        """
        The date and time the PrivilegedApiControl was marked for delete, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_deleted")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the PrivilegedApiControl was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetApiaccesscontrolPrivilegedApiControlResult(GetApiaccesscontrolPrivilegedApiControlResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetApiaccesscontrolPrivilegedApiControlResult(
            approver_group_id_lists=self.approver_group_id_lists,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            notification_topic_id=self.notification_topic_id,
            number_of_approvers=self.number_of_approvers,
            privileged_api_control_id=self.privileged_api_control_id,
            privileged_operation_lists=self.privileged_operation_lists,
            resource_type=self.resource_type,
            resources=self.resources,
            state=self.state,
            state_details=self.state_details,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_deleted=self.time_deleted,
            time_updated=self.time_updated)


def get_apiaccesscontrol_privileged_api_control(privileged_api_control_id: Optional[_builtins.str] = None,
                                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetApiaccesscontrolPrivilegedApiControlResult:
    """
    This data source provides details about a specific Privileged Api Control resource in Oracle Cloud Infrastructure Apiaccesscontrol service.

    Gets information about a PrivilegedApiControl.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_privileged_api_control = oci.oci.get_apiaccesscontrol_privileged_api_control(privileged_api_control_id=test_privileged_api_control_oci_apiaccesscontrol_privileged_api_control["id"])
    ```


    :param _builtins.str privileged_api_control_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiControl.
    """
    __args__ = dict()
    __args__['privilegedApiControlId'] = privileged_api_control_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:oci/getApiaccesscontrolPrivilegedApiControl:getApiaccesscontrolPrivilegedApiControl', __args__, opts=opts, typ=GetApiaccesscontrolPrivilegedApiControlResult).value

    return AwaitableGetApiaccesscontrolPrivilegedApiControlResult(
        approver_group_id_lists=pulumi.get(__ret__, 'approver_group_id_lists'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        notification_topic_id=pulumi.get(__ret__, 'notification_topic_id'),
        number_of_approvers=pulumi.get(__ret__, 'number_of_approvers'),
        privileged_api_control_id=pulumi.get(__ret__, 'privileged_api_control_id'),
        privileged_operation_lists=pulumi.get(__ret__, 'privileged_operation_lists'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        resources=pulumi.get(__ret__, 'resources'),
        state=pulumi.get(__ret__, 'state'),
        state_details=pulumi.get(__ret__, 'state_details'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_deleted=pulumi.get(__ret__, 'time_deleted'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_apiaccesscontrol_privileged_api_control_output(privileged_api_control_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                       opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetApiaccesscontrolPrivilegedApiControlResult]:
    """
    This data source provides details about a specific Privileged Api Control resource in Oracle Cloud Infrastructure Apiaccesscontrol service.

    Gets information about a PrivilegedApiControl.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_privileged_api_control = oci.oci.get_apiaccesscontrol_privileged_api_control(privileged_api_control_id=test_privileged_api_control_oci_apiaccesscontrol_privileged_api_control["id"])
    ```


    :param _builtins.str privileged_api_control_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the PrivilegedApiControl.
    """
    __args__ = dict()
    __args__['privilegedApiControlId'] = privileged_api_control_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:oci/getApiaccesscontrolPrivilegedApiControl:getApiaccesscontrolPrivilegedApiControl', __args__, opts=opts, typ=GetApiaccesscontrolPrivilegedApiControlResult)
    return __ret__.apply(lambda __response__: GetApiaccesscontrolPrivilegedApiControlResult(
        approver_group_id_lists=pulumi.get(__response__, 'approver_group_id_lists'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        notification_topic_id=pulumi.get(__response__, 'notification_topic_id'),
        number_of_approvers=pulumi.get(__response__, 'number_of_approvers'),
        privileged_api_control_id=pulumi.get(__response__, 'privileged_api_control_id'),
        privileged_operation_lists=pulumi.get(__response__, 'privileged_operation_lists'),
        resource_type=pulumi.get(__response__, 'resource_type'),
        resources=pulumi.get(__response__, 'resources'),
        state=pulumi.get(__response__, 'state'),
        state_details=pulumi.get(__response__, 'state_details'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_deleted=pulumi.get(__response__, 'time_deleted'),
        time_updated=pulumi.get(__response__, 'time_updated')))
