# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins
import copy
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
    'GetDelegationControlsResult',
    'AwaitableGetDelegationControlsResult',
    'get_delegation_controls',
    'get_delegation_controls_output',
]

@pulumi.output_type
class GetDelegationControlsResult:
    """
    A collection of values returned by getDelegationControls.
    """
    def __init__(__self__, compartment_id=None, delegation_control_summary_collections=None, display_name=None, filters=None, id=None, resource_id=None, resource_type=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if delegation_control_summary_collections and not isinstance(delegation_control_summary_collections, list):
            raise TypeError("Expected argument 'delegation_control_summary_collections' to be a list")
        pulumi.set(__self__, "delegation_control_summary_collections", delegation_control_summary_collections)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if resource_id and not isinstance(resource_id, str):
            raise TypeError("Expected argument 'resource_id' to be a str")
        pulumi.set(__self__, "resource_id", resource_id)
        if resource_type and not isinstance(resource_type, str):
            raise TypeError("Expected argument 'resource_type' to be a str")
        pulumi.set(__self__, "resource_type", resource_type)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> builtins.str:
        """
        The OCID of the compartment that contains the Delegation Control.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="delegationControlSummaryCollections")
    def delegation_control_summary_collections(self) -> Sequence['outputs.GetDelegationControlsDelegationControlSummaryCollectionResult']:
        """
        The list of delegation_control_summary_collection.
        """
        return pulumi.get(self, "delegation_control_summary_collections")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[builtins.str]:
        """
        Name of the Delegation Control. The name does not need to be unique.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDelegationControlsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[builtins.str]:
        return pulumi.get(self, "resource_id")

    @property
    @pulumi.getter(name="resourceType")
    def resource_type(self) -> Optional[builtins.str]:
        """
        Resource type for which the Delegation Control is applicable to.
        """
        return pulumi.get(self, "resource_type")

    @property
    @pulumi.getter
    def state(self) -> Optional[builtins.str]:
        """
        The current lifecycle state of the Delegation Control.
        """
        return pulumi.get(self, "state")


class AwaitableGetDelegationControlsResult(GetDelegationControlsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDelegationControlsResult(
            compartment_id=self.compartment_id,
            delegation_control_summary_collections=self.delegation_control_summary_collections,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            state=self.state)


def get_delegation_controls(compartment_id: Optional[builtins.str] = None,
                            display_name: Optional[builtins.str] = None,
                            filters: Optional[Sequence[Union['GetDelegationControlsFilterArgs', 'GetDelegationControlsFilterArgsDict']]] = None,
                            resource_id: Optional[builtins.str] = None,
                            resource_type: Optional[builtins.str] = None,
                            state: Optional[builtins.str] = None,
                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDelegationControlsResult:
    """
    This data source provides the list of Delegation Controls in Oracle Cloud Infrastructure Delegate Access Control service.

    Lists the Delegation Controls in the compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_delegation_controls = oci.DelegateAccessControl.get_delegation_controls(compartment_id=compartment_id,
        display_name=delegation_control_display_name,
        resource_id=test_resource["id"],
        resource_type=delegation_control_resource_type,
        state=delegation_control_state)
    ```


    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A filter to return Delegation Control resources that match the given display name.
    :param builtins.str resource_id: A filter to return Delegation Control resources that match the given resource ID.
    :param builtins.str resource_type: A filter to return only resources that match the given resource type.
    :param builtins.str state: A filter to return only Delegation Control resources whose lifecycleState matches the given Delegation Control lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['resourceId'] = resource_id
    __args__['resourceType'] = resource_type
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DelegateAccessControl/getDelegationControls:getDelegationControls', __args__, opts=opts, typ=GetDelegationControlsResult).value

    return AwaitableGetDelegationControlsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        delegation_control_summary_collections=pulumi.get(__ret__, 'delegation_control_summary_collections'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        resource_id=pulumi.get(__ret__, 'resource_id'),
        resource_type=pulumi.get(__ret__, 'resource_type'),
        state=pulumi.get(__ret__, 'state'))
def get_delegation_controls_output(compartment_id: Optional[pulumi.Input[builtins.str]] = None,
                                   display_name: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   filters: Optional[pulumi.Input[Optional[Sequence[Union['GetDelegationControlsFilterArgs', 'GetDelegationControlsFilterArgsDict']]]]] = None,
                                   resource_id: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   resource_type: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   state: Optional[pulumi.Input[Optional[builtins.str]]] = None,
                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDelegationControlsResult]:
    """
    This data source provides the list of Delegation Controls in Oracle Cloud Infrastructure Delegate Access Control service.

    Lists the Delegation Controls in the compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_delegation_controls = oci.DelegateAccessControl.get_delegation_controls(compartment_id=compartment_id,
        display_name=delegation_control_display_name,
        resource_id=test_resource["id"],
        resource_type=delegation_control_resource_type,
        state=delegation_control_state)
    ```


    :param builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param builtins.str display_name: A filter to return Delegation Control resources that match the given display name.
    :param builtins.str resource_id: A filter to return Delegation Control resources that match the given resource ID.
    :param builtins.str resource_type: A filter to return only resources that match the given resource type.
    :param builtins.str state: A filter to return only Delegation Control resources whose lifecycleState matches the given Delegation Control lifecycle state.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['resourceId'] = resource_id
    __args__['resourceType'] = resource_type
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DelegateAccessControl/getDelegationControls:getDelegationControls', __args__, opts=opts, typ=GetDelegationControlsResult)
    return __ret__.apply(lambda __response__: GetDelegationControlsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        delegation_control_summary_collections=pulumi.get(__response__, 'delegation_control_summary_collections'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        resource_id=pulumi.get(__response__, 'resource_id'),
        resource_type=pulumi.get(__response__, 'resource_type'),
        state=pulumi.get(__response__, 'state')))
