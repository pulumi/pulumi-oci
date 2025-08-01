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
    'GetAlarmStatusesResult',
    'AwaitableGetAlarmStatusesResult',
    'get_alarm_statuses',
    'get_alarm_statuses_output',
]

@pulumi.output_type
class GetAlarmStatusesResult:
    """
    A collection of values returned by getAlarmStatuses.
    """
    def __init__(__self__, alarm_statuses=None, compartment_id=None, compartment_id_in_subtree=None, display_name=None, entity_id=None, filters=None, id=None, resource_id=None, service_name=None, status=None):
        if alarm_statuses and not isinstance(alarm_statuses, list):
            raise TypeError("Expected argument 'alarm_statuses' to be a list")
        pulumi.set(__self__, "alarm_statuses", alarm_statuses)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compartment_id_in_subtree and not isinstance(compartment_id_in_subtree, bool):
            raise TypeError("Expected argument 'compartment_id_in_subtree' to be a bool")
        pulumi.set(__self__, "compartment_id_in_subtree", compartment_id_in_subtree)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if entity_id and not isinstance(entity_id, str):
            raise TypeError("Expected argument 'entity_id' to be a str")
        pulumi.set(__self__, "entity_id", entity_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if resource_id and not isinstance(resource_id, str):
            raise TypeError("Expected argument 'resource_id' to be a str")
        pulumi.set(__self__, "resource_id", resource_id)
        if service_name and not isinstance(service_name, str):
            raise TypeError("Expected argument 'service_name' to be a str")
        pulumi.set(__self__, "service_name", service_name)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)

    @_builtins.property
    @pulumi.getter(name="alarmStatuses")
    def alarm_statuses(self) -> Sequence['outputs.GetAlarmStatusesAlarmStatusResult']:
        """
        The list of alarm_statuses.
        """
        return pulumi.get(self, "alarm_statuses")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="compartmentIdInSubtree")
    def compartment_id_in_subtree(self) -> Optional[_builtins.bool]:
        return pulumi.get(self, "compartment_id_in_subtree")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> Optional[_builtins.str]:
        """
        The configured name of the alarm.  Example: `High CPU Utilization`
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="entityId")
    def entity_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "entity_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetAlarmStatusesFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="resourceId")
    def resource_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "resource_id")

    @_builtins.property
    @pulumi.getter(name="serviceName")
    def service_name(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "service_name")

    @_builtins.property
    @pulumi.getter
    def status(self) -> Optional[_builtins.str]:
        """
        The status of this alarm. Status is collective, across all metric streams in the alarm. To list alarm status for each metric stream, use [RetrieveDimensionStates](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmDimensionStatesCollection/RetrieveDimensionStates).  Example: `FIRING`
        """
        return pulumi.get(self, "status")


class AwaitableGetAlarmStatusesResult(GetAlarmStatusesResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAlarmStatusesResult(
            alarm_statuses=self.alarm_statuses,
            compartment_id=self.compartment_id,
            compartment_id_in_subtree=self.compartment_id_in_subtree,
            display_name=self.display_name,
            entity_id=self.entity_id,
            filters=self.filters,
            id=self.id,
            resource_id=self.resource_id,
            service_name=self.service_name,
            status=self.status)


def get_alarm_statuses(compartment_id: Optional[_builtins.str] = None,
                       compartment_id_in_subtree: Optional[_builtins.bool] = None,
                       display_name: Optional[_builtins.str] = None,
                       entity_id: Optional[_builtins.str] = None,
                       filters: Optional[Sequence[Union['GetAlarmStatusesFilterArgs', 'GetAlarmStatusesFilterArgsDict']]] = None,
                       resource_id: Optional[_builtins.str] = None,
                       service_name: Optional[_builtins.str] = None,
                       status: Optional[_builtins.str] = None,
                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAlarmStatusesResult:
    """
    This data source provides the list of Alarm Statuses in Oracle Cloud Infrastructure Monitoring service.

    List the status of each alarm in the specified compartment.
    Status is collective, across all metric streams in the alarm.
    To list alarm status for each metric stream, use [RetrieveDimensionStates](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmDimensionStatesCollection/RetrieveDimensionStates).
    Optionally filter by resource or status value.

    For more information, see
    [Listing Alarm Statuses](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/list-alarm-status.htm).
    For important limits information, see
    [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).

    This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
    Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
    or transactions, per second (TPS) for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alarm_statuses = oci.Monitoring.get_alarm_statuses(compartment_id=compartment_id,
        compartment_id_in_subtree=alarm_status_compartment_id_in_subtree,
        display_name=alarm_status_display_name,
        entity_id=test_entity["id"],
        resource_id=test_resource["id"],
        service_name=test_service["name"],
        status=alarm_status_status)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
    :param _builtins.bool compartment_id_in_subtree: When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
    :param _builtins.str entity_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the entity monitored by the metric that you are searching for.  Example: `ocid1.instance.oc1.phx.exampleuniqueID`
    :param _builtins.str resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a resource that is monitored by the metric that you are searching for.  Example: `ocid1.instance.oc1.phx.exampleuniqueID`
    :param _builtins.str service_name: A filter to return only resources that match the given service name exactly. Use this filter to list all alarms containing metric streams that match the *exact* service-name dimension.  Example: `logging-analytics`
    :param _builtins.str status: The status of the metric stream to use for alarm filtering. For example, set `StatusQueryParam` to "FIRING" to filter results to metric streams of the alarm with that status. Default behaviour is to return alarms irrespective of metric streams' status.  Example: `FIRING`
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['resourceId'] = resource_id
    __args__['serviceName'] = service_name
    __args__['status'] = status
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Monitoring/getAlarmStatuses:getAlarmStatuses', __args__, opts=opts, typ=GetAlarmStatusesResult).value

    return AwaitableGetAlarmStatusesResult(
        alarm_statuses=pulumi.get(__ret__, 'alarm_statuses'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__ret__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__ret__, 'display_name'),
        entity_id=pulumi.get(__ret__, 'entity_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        resource_id=pulumi.get(__ret__, 'resource_id'),
        service_name=pulumi.get(__ret__, 'service_name'),
        status=pulumi.get(__ret__, 'status'))
def get_alarm_statuses_output(compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                              compartment_id_in_subtree: Optional[pulumi.Input[Optional[_builtins.bool]]] = None,
                              display_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              entity_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              filters: Optional[pulumi.Input[Optional[Sequence[Union['GetAlarmStatusesFilterArgs', 'GetAlarmStatusesFilterArgsDict']]]]] = None,
                              resource_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              service_name: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              status: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAlarmStatusesResult]:
    """
    This data source provides the list of Alarm Statuses in Oracle Cloud Infrastructure Monitoring service.

    List the status of each alarm in the specified compartment.
    Status is collective, across all metric streams in the alarm.
    To list alarm status for each metric stream, use [RetrieveDimensionStates](https://docs.cloud.oracle.com/iaas/api/#/en/monitoring/latest/AlarmDimensionStatesCollection/RetrieveDimensionStates).
    Optionally filter by resource or status value.

    For more information, see
    [Listing Alarm Statuses](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/list-alarm-status.htm).
    For important limits information, see
    [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).

    This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
    Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
    or transactions, per second (TPS) for a given tenancy.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_alarm_statuses = oci.Monitoring.get_alarm_statuses(compartment_id=compartment_id,
        compartment_id_in_subtree=alarm_status_compartment_id_in_subtree,
        display_name=alarm_status_display_name,
        entity_id=test_entity["id"],
        resource_id=test_resource["id"],
        service_name=test_service["name"],
        status=alarm_status_status)
    ```


    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
    :param _builtins.bool compartment_id_in_subtree: When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
    :param _builtins.str display_name: A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
    :param _builtins.str entity_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the entity monitored by the metric that you are searching for.  Example: `ocid1.instance.oc1.phx.exampleuniqueID`
    :param _builtins.str resource_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a resource that is monitored by the metric that you are searching for.  Example: `ocid1.instance.oc1.phx.exampleuniqueID`
    :param _builtins.str service_name: A filter to return only resources that match the given service name exactly. Use this filter to list all alarms containing metric streams that match the *exact* service-name dimension.  Example: `logging-analytics`
    :param _builtins.str status: The status of the metric stream to use for alarm filtering. For example, set `StatusQueryParam` to "FIRING" to filter results to metric streams of the alarm with that status. Default behaviour is to return alarms irrespective of metric streams' status.  Example: `FIRING`
    """
    __args__ = dict()
    __args__['compartmentId'] = compartment_id
    __args__['compartmentIdInSubtree'] = compartment_id_in_subtree
    __args__['displayName'] = display_name
    __args__['entityId'] = entity_id
    __args__['filters'] = filters
    __args__['resourceId'] = resource_id
    __args__['serviceName'] = service_name
    __args__['status'] = status
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Monitoring/getAlarmStatuses:getAlarmStatuses', __args__, opts=opts, typ=GetAlarmStatusesResult)
    return __ret__.apply(lambda __response__: GetAlarmStatusesResult(
        alarm_statuses=pulumi.get(__response__, 'alarm_statuses'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compartment_id_in_subtree=pulumi.get(__response__, 'compartment_id_in_subtree'),
        display_name=pulumi.get(__response__, 'display_name'),
        entity_id=pulumi.get(__response__, 'entity_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        resource_id=pulumi.get(__response__, 'resource_id'),
        service_name=pulumi.get(__response__, 'service_name'),
        status=pulumi.get(__response__, 'status')))
