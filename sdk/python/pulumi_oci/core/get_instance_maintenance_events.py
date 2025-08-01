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
    'GetInstanceMaintenanceEventsResult',
    'AwaitableGetInstanceMaintenanceEventsResult',
    'get_instance_maintenance_events',
    'get_instance_maintenance_events_output',
]

@pulumi.output_type
class GetInstanceMaintenanceEventsResult:
    """
    A collection of values returned by getInstanceMaintenanceEvents.
    """
    def __init__(__self__, compartment_id=None, correlation_token=None, filters=None, id=None, instance_action=None, instance_id=None, instance_maintenance_events=None, state=None, time_window_start_greater_than_or_equal_to=None, time_window_start_less_than_or_equal_to=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if correlation_token and not isinstance(correlation_token, str):
            raise TypeError("Expected argument 'correlation_token' to be a str")
        pulumi.set(__self__, "correlation_token", correlation_token)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if instance_action and not isinstance(instance_action, str):
            raise TypeError("Expected argument 'instance_action' to be a str")
        pulumi.set(__self__, "instance_action", instance_action)
        if instance_id and not isinstance(instance_id, str):
            raise TypeError("Expected argument 'instance_id' to be a str")
        pulumi.set(__self__, "instance_id", instance_id)
        if instance_maintenance_events and not isinstance(instance_maintenance_events, list):
            raise TypeError("Expected argument 'instance_maintenance_events' to be a list")
        pulumi.set(__self__, "instance_maintenance_events", instance_maintenance_events)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_window_start_greater_than_or_equal_to and not isinstance(time_window_start_greater_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_window_start_greater_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_window_start_greater_than_or_equal_to", time_window_start_greater_than_or_equal_to)
        if time_window_start_less_than_or_equal_to and not isinstance(time_window_start_less_than_or_equal_to, str):
            raise TypeError("Expected argument 'time_window_start_less_than_or_equal_to' to be a str")
        pulumi.set(__self__, "time_window_start_less_than_or_equal_to", time_window_start_less_than_or_equal_to)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The OCID of the compartment that contains the instance.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="correlationToken")
    def correlation_token(self) -> Optional[_builtins.str]:
        """
        A unique identifier that will group Instances that have a relationship with one another and must be scheduled together for the Maintenance to proceed. Any Instances that have a relationship with one another from a Maintenance perspective will have a matching correlationToken.
        """
        return pulumi.get(self, "correlation_token")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetInstanceMaintenanceEventsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="instanceAction")
    def instance_action(self) -> Optional[_builtins.str]:
        """
        This is the action that will be performed on the Instance by Oracle Cloud Infrastructure when the Maintenance begins.
        """
        return pulumi.get(self, "instance_action")

    @_builtins.property
    @pulumi.getter(name="instanceId")
    def instance_id(self) -> Optional[_builtins.str]:
        """
        The OCID of the instance.
        """
        return pulumi.get(self, "instance_id")

    @_builtins.property
    @pulumi.getter(name="instanceMaintenanceEvents")
    def instance_maintenance_events(self) -> Sequence['outputs.GetInstanceMaintenanceEventsInstanceMaintenanceEventResult']:
        """
        The list of instance_maintenance_events.
        """
        return pulumi.get(self, "instance_maintenance_events")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current state of the maintenance event.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="timeWindowStartGreaterThanOrEqualTo")
    def time_window_start_greater_than_or_equal_to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_window_start_greater_than_or_equal_to")

    @_builtins.property
    @pulumi.getter(name="timeWindowStartLessThanOrEqualTo")
    def time_window_start_less_than_or_equal_to(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_window_start_less_than_or_equal_to")


class AwaitableGetInstanceMaintenanceEventsResult(GetInstanceMaintenanceEventsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetInstanceMaintenanceEventsResult(
            compartment_id=self.compartment_id,
            correlation_token=self.correlation_token,
            filters=self.filters,
            id=self.id,
            instance_action=self.instance_action,
            instance_id=self.instance_id,
            instance_maintenance_events=self.instance_maintenance_events,
            state=self.state,
            time_window_start_greater_than_or_equal_to=self.time_window_start_greater_than_or_equal_to,
            time_window_start_less_than_or_equal_to=self.time_window_start_less_than_or_equal_to)


def get_instance_maintenance_events(compartment_id: Optional[_builtins.str] = None,
                                    correlation_token: Optional[_builtins.str] = None,
                                    filters: Optional[Sequence[Union['GetInstanceMaintenanceEventsFilterArgs', 'GetInstanceMaintenanceEventsFilterArgsDict']]] = None,
                                    instance_action: Optional[_builtins.str] = None,
                                    instance_id: Optional[_builtins.str] = None,
                                    state: Optional[_builtins.str] = None,
                                    time_window_start_greater_than_or_equal_to: Optional[_builtins.str] = None,
                                    time_window_start_less_than_or_equal_to: Optional[_builtins.str] = None,
                                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetInstanceMaintenanceEventsResult:
    """
    This data source provides the list of Instance Maintenance Events in Oracle Cloud Infrastructure Core service.

    Gets a list of all the maintenance events for the given instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_maintenance_events = oci.Core.get_instance_maintenance_events(compartment_id=compartment_id,
        correlation_token=instance_maintenance_event_correlation_token,
        instance_action=instance_maintenance_event_instance_action,
        instance_id=test_instance["id"],
        state=instance_maintenance_event_state,
        time_window_start_greater_than_or_equal_to=instance_maintenance_event_time_window_start_greater_than_or_equal_to,
        time_window_start_less_than_or_equal_to=instance_maintenance_event_time_window_start_less_than_or_equal_to)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str correlation_token: A filter to only return resources that have a matching correlationToken.
    :param _builtins.str instance_action: A filter to only return resources that match the given instance action.
    :param _builtins.str instance_id: The OCID of the instance.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.
    :param _builtins.str time_window_start_greater_than_or_equal_to: Starting range to return the maintenances which are not completed (date-time is in [RFC3339](https://tools.ietf.org/html/rfc3339) format).
    :param _builtins.str time_window_start_less_than_or_equal_to: Ending range to return the maintenances which are not completed (date-time is in [RFC3339](https://tools.ietf.org/html/rfc3339) format).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['correlationToken'] = correlation_token
    __args__['filters'] = filters
    __args__['instanceAction'] = instance_action
    __args__['instanceId'] = instance_id
    __args__['state'] = state
    __args__['timeWindowStartGreaterThanOrEqualTo'] = time_window_start_greater_than_or_equal_to
    __args__['timeWindowStartLessThanOrEqualTo'] = time_window_start_less_than_or_equal_to
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Core/getInstanceMaintenanceEvents:getInstanceMaintenanceEvents', __args__, opts=opts, typ=GetInstanceMaintenanceEventsResult).value

    return AwaitableGetInstanceMaintenanceEventsResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        correlation_token=pulumi.get(__ret__, 'correlation_token'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        instance_action=pulumi.get(__ret__, 'instance_action'),
        instance_id=pulumi.get(__ret__, 'instance_id'),
        instance_maintenance_events=pulumi.get(__ret__, 'instance_maintenance_events'),
        state=pulumi.get(__ret__, 'state'),
        time_window_start_greater_than_or_equal_to=pulumi.get(__ret__, 'time_window_start_greater_than_or_equal_to'),
        time_window_start_less_than_or_equal_to=pulumi.get(__ret__, 'time_window_start_less_than_or_equal_to'))
def get_instance_maintenance_events_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                           correlation_token: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           filters: Optional[pulumi.Input[Optional[Sequence[Union['GetInstanceMaintenanceEventsFilterArgs', 'GetInstanceMaintenanceEventsFilterArgsDict']]]]] = None,
                                           instance_action: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           instance_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           time_window_start_greater_than_or_equal_to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           time_window_start_less_than_or_equal_to: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                           opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetInstanceMaintenanceEventsResult]:
    """
    This data source provides the list of Instance Maintenance Events in Oracle Cloud Infrastructure Core service.

    Gets a list of all the maintenance events for the given instance.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_instance_maintenance_events = oci.Core.get_instance_maintenance_events(compartment_id=compartment_id,
        correlation_token=instance_maintenance_event_correlation_token,
        instance_action=instance_maintenance_event_instance_action,
        instance_id=test_instance["id"],
        state=instance_maintenance_event_state,
        time_window_start_greater_than_or_equal_to=instance_maintenance_event_time_window_start_greater_than_or_equal_to,
        time_window_start_less_than_or_equal_to=instance_maintenance_event_time_window_start_less_than_or_equal_to)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
    :param _builtins.str correlation_token: A filter to only return resources that have a matching correlationToken.
    :param _builtins.str instance_action: A filter to only return resources that match the given instance action.
    :param _builtins.str instance_id: The OCID of the instance.
    :param _builtins.str state: A filter to only return resources that match the given lifecycle state.
    :param _builtins.str time_window_start_greater_than_or_equal_to: Starting range to return the maintenances which are not completed (date-time is in [RFC3339](https://tools.ietf.org/html/rfc3339) format).
    :param _builtins.str time_window_start_less_than_or_equal_to: Ending range to return the maintenances which are not completed (date-time is in [RFC3339](https://tools.ietf.org/html/rfc3339) format).
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['correlationToken'] = correlation_token
    __args__['filters'] = filters
    __args__['instanceAction'] = instance_action
    __args__['instanceId'] = instance_id
    __args__['state'] = state
    __args__['timeWindowStartGreaterThanOrEqualTo'] = time_window_start_greater_than_or_equal_to
    __args__['timeWindowStartLessThanOrEqualTo'] = time_window_start_less_than_or_equal_to
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Core/getInstanceMaintenanceEvents:getInstanceMaintenanceEvents', __args__, opts=opts, typ=GetInstanceMaintenanceEventsResult)
    return __ret__.apply(lambda __response__: GetInstanceMaintenanceEventsResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        correlation_token=pulumi.get(__response__, 'correlation_token'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        instance_action=pulumi.get(__response__, 'instance_action'),
        instance_id=pulumi.get(__response__, 'instance_id'),
        instance_maintenance_events=pulumi.get(__response__, 'instance_maintenance_events'),
        state=pulumi.get(__response__, 'state'),
        time_window_start_greater_than_or_equal_to=pulumi.get(__response__, 'time_window_start_greater_than_or_equal_to'),
        time_window_start_less_than_or_equal_to=pulumi.get(__response__, 'time_window_start_less_than_or_equal_to')))
