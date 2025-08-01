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
    'GetMonitoringTemplateAlarmConditionsResult',
    'AwaitableGetMonitoringTemplateAlarmConditionsResult',
    'get_monitoring_template_alarm_conditions',
    'get_monitoring_template_alarm_conditions_output',
]

@pulumi.output_type
class GetMonitoringTemplateAlarmConditionsResult:
    """
    A collection of values returned by getMonitoringTemplateAlarmConditions.
    """
    def __init__(__self__, alarm_condition_collections=None, alarm_condition_id=None, compartment_id=None, filters=None, id=None, metric_names=None, monitoring_template_id=None, resource_types=None, state=None, status=None):
        if alarm_condition_collections and not isinstance(alarm_condition_collections, list):
            raise TypeError("Expected argument 'alarm_condition_collections' to be a list")
        pulumi.set(__self__, "alarm_condition_collections", alarm_condition_collections)
        if alarm_condition_id and not isinstance(alarm_condition_id, str):
            raise TypeError("Expected argument 'alarm_condition_id' to be a str")
        pulumi.set(__self__, "alarm_condition_id", alarm_condition_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if metric_names and not isinstance(metric_names, list):
            raise TypeError("Expected argument 'metric_names' to be a list")
        pulumi.set(__self__, "metric_names", metric_names)
        if monitoring_template_id and not isinstance(monitoring_template_id, str):
            raise TypeError("Expected argument 'monitoring_template_id' to be a str")
        pulumi.set(__self__, "monitoring_template_id", monitoring_template_id)
        if resource_types and not isinstance(resource_types, list):
            raise TypeError("Expected argument 'resource_types' to be a list")
        pulumi.set(__self__, "resource_types", resource_types)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)

    @_builtins.property
    @pulumi.getter(name="alarmConditionCollections")
    def alarm_condition_collections(self) -> Sequence['outputs.GetMonitoringTemplateAlarmConditionsAlarmConditionCollectionResult']:
        """
        The list of alarm_condition_collection.
        """
        return pulumi.get(self, "alarm_condition_collections")

    @_builtins.property
    @pulumi.getter(name="alarmConditionId")
    def alarm_condition_id(self) -> _builtins.str:
        return pulumi.get(self, "alarm_condition_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMonitoringTemplateAlarmConditionsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="metricNames")
    def metric_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        The metric name.
        """
        return pulumi.get(self, "metric_names")

    @_builtins.property
    @pulumi.getter(name="monitoringTemplateId")
    def monitoring_template_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        """
        return pulumi.get(self, "monitoring_template_id")

    @_builtins.property
    @pulumi.getter(name="resourceTypes")
    def resource_types(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "resource_types")

    @_builtins.property
    @pulumi.getter
    def state(self) -> Optional[_builtins.str]:
        """
        The current lifecycle state of the monitoring template
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def status(self) -> Optional[_builtins.str]:
        """
        The current status of the monitoring template i.e. whether it is Published or Unpublished
        """
        return pulumi.get(self, "status")


class AwaitableGetMonitoringTemplateAlarmConditionsResult(GetMonitoringTemplateAlarmConditionsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMonitoringTemplateAlarmConditionsResult(
            alarm_condition_collections=self.alarm_condition_collections,
            alarm_condition_id=self.alarm_condition_id,
            compartment_id=self.compartment_id,
            filters=self.filters,
            id=self.id,
            metric_names=self.metric_names,
            monitoring_template_id=self.monitoring_template_id,
            resource_types=self.resource_types,
            state=self.state,
            status=self.status)


def get_monitoring_template_alarm_conditions(alarm_condition_id: Optional[_builtins.str] = None,
                                             compartment_id: Optional[_builtins.str] = None,
                                             filters: Optional[Sequence[Union['GetMonitoringTemplateAlarmConditionsFilterArgs', 'GetMonitoringTemplateAlarmConditionsFilterArgsDict']]] = None,
                                             metric_names: Optional[Sequence[_builtins.str]] = None,
                                             monitoring_template_id: Optional[_builtins.str] = None,
                                             resource_types: Optional[Sequence[_builtins.str]] = None,
                                             state: Optional[_builtins.str] = None,
                                             status: Optional[_builtins.str] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMonitoringTemplateAlarmConditionsResult:
    """
    This data source provides the list of Monitoring Template Alarm Conditions in Oracle Cloud Infrastructure Stack Monitoring service.

    Returns a list of Alarm Conditions.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitoring_template_alarm_conditions = oci.StackMonitoring.get_monitoring_template_alarm_conditions(monitoring_template_id=test_monitoring_template["id"],
        metric_names=test_metric["name"],
        resource_types=monitoring_template_alarm_condition_resource_types,
        state=monitoring_template_alarm_condition_state,
        status=monitoring_template_alarm_condition_status)
    ```


    :param Sequence[_builtins.str] metric_names: metricName filter.
    :param _builtins.str monitoring_template_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
    :param Sequence[_builtins.str] resource_types: Multiple resource types filter.
    :param _builtins.str state: A filter to return alarm condition based on Lifecycle State.
    :param _builtins.str status: A filter to return alarm condition based on input status.
    """
    __args__ = dict()
    __args__['alarmConditionId'] = alarm_condition_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['metricNames'] = metric_names
    __args__['monitoringTemplateId'] = monitoring_template_id
    __args__['resourceTypes'] = resource_types
    __args__['state'] = state
    __args__['status'] = status
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:StackMonitoring/getMonitoringTemplateAlarmConditions:getMonitoringTemplateAlarmConditions', __args__, opts=opts, typ=GetMonitoringTemplateAlarmConditionsResult).value

    return AwaitableGetMonitoringTemplateAlarmConditionsResult(
        alarm_condition_collections=pulumi.get(__ret__, 'alarm_condition_collections'),
        alarm_condition_id=pulumi.get(__ret__, 'alarm_condition_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        metric_names=pulumi.get(__ret__, 'metric_names'),
        monitoring_template_id=pulumi.get(__ret__, 'monitoring_template_id'),
        resource_types=pulumi.get(__ret__, 'resource_types'),
        state=pulumi.get(__ret__, 'state'),
        status=pulumi.get(__ret__, 'status'))
def get_monitoring_template_alarm_conditions_output(alarm_condition_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMonitoringTemplateAlarmConditionsFilterArgs', 'GetMonitoringTemplateAlarmConditionsFilterArgsDict']]]]] = None,
                                                    metric_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                    monitoring_template_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    resource_types: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                    state: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    status: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMonitoringTemplateAlarmConditionsResult]:
    """
    This data source provides the list of Monitoring Template Alarm Conditions in Oracle Cloud Infrastructure Stack Monitoring service.

    Returns a list of Alarm Conditions.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitoring_template_alarm_conditions = oci.StackMonitoring.get_monitoring_template_alarm_conditions(monitoring_template_id=test_monitoring_template["id"],
        metric_names=test_metric["name"],
        resource_types=monitoring_template_alarm_condition_resource_types,
        state=monitoring_template_alarm_condition_state,
        status=monitoring_template_alarm_condition_status)
    ```


    :param Sequence[_builtins.str] metric_names: metricName filter.
    :param _builtins.str monitoring_template_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
    :param Sequence[_builtins.str] resource_types: Multiple resource types filter.
    :param _builtins.str state: A filter to return alarm condition based on Lifecycle State.
    :param _builtins.str status: A filter to return alarm condition based on input status.
    """
    __args__ = dict()
    __args__['alarmConditionId'] = alarm_condition_id
    __args__['compartmentId'] = compartment_id
    __args__['filters'] = filters
    __args__['metricNames'] = metric_names
    __args__['monitoringTemplateId'] = monitoring_template_id
    __args__['resourceTypes'] = resource_types
    __args__['state'] = state
    __args__['status'] = status
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:StackMonitoring/getMonitoringTemplateAlarmConditions:getMonitoringTemplateAlarmConditions', __args__, opts=opts, typ=GetMonitoringTemplateAlarmConditionsResult)
    return __ret__.apply(lambda __response__: GetMonitoringTemplateAlarmConditionsResult(
        alarm_condition_collections=pulumi.get(__response__, 'alarm_condition_collections'),
        alarm_condition_id=pulumi.get(__response__, 'alarm_condition_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        metric_names=pulumi.get(__response__, 'metric_names'),
        monitoring_template_id=pulumi.get(__response__, 'monitoring_template_id'),
        resource_types=pulumi.get(__response__, 'resource_types'),
        state=pulumi.get(__response__, 'state'),
        status=pulumi.get(__response__, 'status')))
