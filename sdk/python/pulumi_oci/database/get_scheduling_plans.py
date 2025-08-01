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
    'GetSchedulingPlansResult',
    'AwaitableGetSchedulingPlansResult',
    'get_scheduling_plans',
    'get_scheduling_plans_output',
]

@pulumi.output_type
class GetSchedulingPlansResult:
    """
    A collection of values returned by getSchedulingPlans.
    """
    def __init__(__self__, compartment_id=None, display_name=None, filters=None, id=None, resource_id=None, scheduling_plan_collections=None, scheduling_policy_id=None, state=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
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
        if scheduling_plan_collections and not isinstance(scheduling_plan_collections, list):
            raise TypeError("Expected argument 'scheduling_plan_collections' to be a list")
        pulumi.set(__self__, "scheduling_plan_collections", scheduling_plan_collections)
        if scheduling_policy_id and not isinstance(scheduling_policy_id, str):
            raise TypeError("Expected argument 'scheduling_policy_id' to be a str")
        pulumi.set(__self__, "scheduling_policy_id", scheduling_policy_id)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The display name of the Scheduling Plan.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetSchedulingPlansFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Plan.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
        """
        return pulumi.get(self, "resource_id")

    @_builtins.property
    @pulumi.getter(name="schedulingPlanCollections")
    def scheduling_plan_collections(self) -> Sequence['outputs.GetSchedulingPlansSchedulingPlanCollectionResult']:
        """
        The list of scheduling_plan_collection.
        """
        return pulumi.get(self, "scheduling_plan_collections")

    @_builtins.property
    @pulumi.getter(name="schedulingPolicyId")
    def scheduling_policy_id(self) -> Optional[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Scheduling Policy.
        """
        return pulumi.get(self, "scheduling_policy_id")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the Scheduling Plan. Valid states are CREATING, NEEDS_ATTENTION, AVAILABLE, UPDATING, FAILED, DELETING and DELETED.
        """
        return pulumi.get(self, "state")


class AwaitableGetSchedulingPlansResult(GetSchedulingPlansResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetSchedulingPlansResult(
            compartment_id=self.compartment_id,
            display_name=self.display_name,
            filters=self.filters,
            id=self.id,
            resource_id=self.resource_id,
            scheduling_plan_collections=self.scheduling_plan_collections,
            scheduling_policy_id=self.scheduling_policy_id,
            state=self.state)


def get_scheduling_plans(compartment_id: Optional[_builtins.str] = None,
                         display_name: Optional[_builtins.str] = None,
                         filters: Optional[Sequence[Union['GetSchedulingPlansFilterArgs', 'GetSchedulingPlansFilterArgsDict']]] = None,
                         id: Optional[_builtins.str] = None,
                         resource_id: Optional[_builtins.str] = None,
                         scheduling_policy_id: Optional[_builtins.str] = None,
                         state: Optional[_builtins.str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetSchedulingPlansResult:
    """
    This data source provides the list of Scheduling Plans in Oracle Cloud Infrastructure Database service.

    Lists the Scheduling Plan resources in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_scheduling_plans = oci.Database.get_scheduling_plans(compartment_id=compartment_id,
        display_name=scheduling_plan_display_name,
        id=scheduling_plan_id,
        resource_id=test_resource["id"],
        scheduling_policy_id=test_scheduling_policy["id"],
        state=scheduling_plan_state)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str id: A filter to return only resources that match the given Schedule Plan id exactly.
    :param _builtins.str resource_id: A filter to return only resources that match the given resource id exactly.
    :param _builtins.str scheduling_policy_id: A filter to return only resources that match the given scheduling policy id exactly.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['resourceId'] = resource_id
    __args__['schedulingPolicyId'] = scheduling_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getSchedulingPlans:getSchedulingPlans', __args__, opts=opts, typ=GetSchedulingPlansResult).value

    return AwaitableGetSchedulingPlansResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        display_name=pulumi.get(__ret__, 'display_name'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        resource_id=pulumi.get(__ret__, 'resource_id'),
        scheduling_plan_collections=pulumi.get(__ret__, 'scheduling_plan_collections'),
        scheduling_policy_id=pulumi.get(__ret__, 'scheduling_policy_id'),
        state=pulumi.get(__ret__, 'state'))
def get_scheduling_plans_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                filters: Optional[pulumi.Input[Optional[Sequence[Union['GetSchedulingPlansFilterArgs', 'GetSchedulingPlansFilterArgsDict']]]]] = None,
                                id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                resource_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                scheduling_policy_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetSchedulingPlansResult]:
    """
    This data source provides the list of Scheduling Plans in Oracle Cloud Infrastructure Database service.

    Lists the Scheduling Plan resources in the specified compartment.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_scheduling_plans = oci.Database.get_scheduling_plans(compartment_id=compartment_id,
        display_name=scheduling_plan_display_name,
        id=scheduling_plan_id,
        resource_id=test_resource["id"],
        scheduling_policy_id=test_scheduling_policy["id"],
        state=scheduling_plan_state)
    ```


    :param _builtins.str compartment_id: The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param _builtins.str display_name: A filter to return only resources that match the entire display name given. The match is not case sensitive.
    :param _builtins.str id: A filter to return only resources that match the given Schedule Plan id exactly.
    :param _builtins.str resource_id: A filter to return only resources that match the given resource id exactly.
    :param _builtins.str scheduling_policy_id: A filter to return only resources that match the given scheduling policy id exactly.
    :param _builtins.str state: A filter to return only resources that match the given lifecycle state exactly.
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['displayName'] = display_name
    __args__['filters'] = filters
    __args__['id'] = id
    __args__['resourceId'] = resource_id
    __args__['schedulingPolicyId'] = scheduling_policy_id
    __args__['state'] = state
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getSchedulingPlans:getSchedulingPlans', __args__, opts=opts, typ=GetSchedulingPlansResult)
    return __ret__.apply(lambda __response__: GetSchedulingPlansResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        display_name=pulumi.get(__response__, 'display_name'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        resource_id=pulumi.get(__response__, 'resource_id'),
        scheduling_plan_collections=pulumi.get(__response__, 'scheduling_plan_collections'),
        scheduling_policy_id=pulumi.get(__response__, 'scheduling_policy_id'),
        state=pulumi.get(__response__, 'state')))
