# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs
from ._inputs import *

__all__ = [
    'GetDrProtectionGroupsResult',
    'AwaitableGetDrProtectionGroupsResult',
    'get_dr_protection_groups',
    'get_dr_protection_groups_output',
]

@pulumi.output_type
class GetDrProtectionGroupsResult:
    """
    A collection of values returned by getDrProtectionGroups.
    """
    def __init__(__self__, compartment_id=None, display_name=None, dr_protection_group_collections=None, dr_protection_group_id=None, filters=None, id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if dr_protection_group_collections and not isinstance(dr_protection_group_collections, list):
            raise TypeError("Expected argument 'dr_protection_group_collections' to be a list")
        pulumi.set(__self__, "dr_protection_group_collections", dr_protection_group_collections)
        if dr_protection_group_id and not isinstance(dr_protection_group_id, str):
            raise TypeError("Expected argument 'dr_protection_group_id' to be a str")
        pulumi.set(__self__, "dr_protection_group_id", dr_protection_group_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment containing the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[str]:
        """
        The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="drProtectionGroupCollections")
    def dr_protection_group_collections(self) -> Sequence['outputs.GetDrProtectionGroupsDrProtectionGroupCollectionResult']:
        """
        The list of dr_protection_group_collection.
        """
        return pulumi.get(self, "dr_protection_group_collections")

    @property
    @pulumi.getter(name="drProtectionGroupId")
    def dr_protection_group_id(self) -> Optional[str]:
        return pulumi.get(self, "dr_protection_group_id")

    @property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetDrProtectionGroupsFilterResult']]:
        return pulumi.get(self, "filters")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter
    def state(self) -> Optional[str]:
        """
        The current state of the DR Protection Group.
        """
        return pulumi.get(self, "state")


class AwaitableGetDrProtectionGroupsResult(GetDrProtectionGroupsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDrProtectionGroupsResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            dr_protection_group_collections=self.dr_protection_group_collections,
            dr_protection_group_id=self.dr_protection_group_id,
            filters=self.filters,
            id=self.id,
            state=self.state)


def get_dr_protection_groups(compartment_id: Optional[str] = None,
                             display_name: Optional[str] = None,
                             dr_protection_group_id: Optional[str] = None,
                             filters: Optional[Sequence[pulumi.InputType['GetDrProtectionGroupsFilterArgs']]] = None,
                             state: Optional[str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDrProtectionGroupsResult:
    """
    This data source provides the list of Dr Protection Groups in Oracle Cloud Infrastructure Disaster Recovery service.

    Gets a summary list of all DR Protection Groups in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dr_protection_groups = oci.DisasterRecovery.get_dr_protection_groups(compartment_id=var["compartment_id"],
        display_name=var["dr_protection_group_display_name"],
        dr_protection_group_id=oci_disaster_recovery_dr_protection_group["test_dr_protection_group"]["id"],
        state=var["dr_protection_group_state"])
    ```


    :param str compartment_id: The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
    :param str display_name: A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
    :param str dr_protection_group_id: The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
    :param str state: A filter to return only DR Protection Groups that match the given lifecycleState.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['drProtectionGroupId'] = dr_protection_group_id
    __args__['filters'] = filters
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DisasterRecovery/getDrProtectionGroups:getDrProtectionGroups', __args__, opts=opts, typ=GetDrProtectionGroupsResult).value

    return AwaitableGetDrProtectionGroupsResult(
        compartment_id=__ret__.compartment_id,
        display_name=__ret__.display_name,
        dr_protection_group_collections=__ret__.dr_protection_group_collections,
        dr_protection_group_id=__ret__.dr_protection_group_id,
        filters=__ret__.filters,
        id=__ret__.id,
        state=__ret__.state)


@_utilities.lift_output_func(get_dr_protection_groups)
def get_dr_protection_groups_output(compartment_id: Optional[pulumi.Input[str]] = None,
                                    display_name: Optional[pulumi.Input[Optional[str]]] = None,
                                    dr_protection_group_id: Optional[pulumi.Input[Optional[str]]] = None,
                                    filters: Optional[pulumi.Input[Optional[Sequence[pulumi.InputType['GetDrProtectionGroupsFilterArgs']]]]] = None,
                                    state: Optional[pulumi.Input[Optional[str]]] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetDrProtectionGroupsResult]:
    """
    This data source provides the list of Dr Protection Groups in Oracle Cloud Infrastructure Disaster Recovery service.

    Gets a summary list of all DR Protection Groups in a compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_dr_protection_groups = oci.DisasterRecovery.get_dr_protection_groups(compartment_id=var["compartment_id"],
        display_name=var["dr_protection_group_display_name"],
        dr_protection_group_id=oci_disaster_recovery_dr_protection_group["test_dr_protection_group"]["id"],
        state=var["dr_protection_group_state"])
    ```


    :param str compartment_id: The ID (OCID) of the compartment in which to list resources.  Example: `ocid1.compartment.oc1..exampleocid1`
    :param str display_name: A filter to return only resources that match the entire display name given.  Example: `MY UNIQUE DISPLAY NAME`
    :param str dr_protection_group_id: The OCID of the DR Protection Group. Optional query param.  Example: `ocid1.drprotectiongroup.oc1.phx.exampleocid`
    :param str state: A filter to return only DR Protection Groups that match the given lifecycleState.
    """
    ...