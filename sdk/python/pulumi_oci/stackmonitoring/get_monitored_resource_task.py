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

__all__ = [
    'GetMonitoredResourceTaskResult',
    'AwaitableGetMonitoredResourceTaskResult',
    'get_monitored_resource_task',
    'get_monitored_resource_task_output',
]

@pulumi.output_type
class GetMonitoredResourceTaskResult:
    """
    A collection of values returned by getMonitoredResourceTask.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, freeform_tags=None, id=None, monitored_resource_task_id=None, name=None, state=None, system_tags=None, task_details=None, tenant_id=None, time_created=None, time_updated=None, work_request_ids=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if monitored_resource_task_id and not isinstance(monitored_resource_task_id, str):
            raise TypeError("Expected argument 'monitored_resource_task_id' to be a str")
        pulumi.set(__self__, "monitored_resource_task_id", monitored_resource_task_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if task_details and not isinstance(task_details, list):
            raise TypeError("Expected argument 'task_details' to be a list")
        pulumi.set(__self__, "task_details", task_details)
        if tenant_id and not isinstance(tenant_id, str):
            raise TypeError("Expected argument 'tenant_id' to be a str")
        pulumi.set(__self__, "tenant_id", tenant_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)
        if work_request_ids and not isinstance(work_request_ids, list):
            raise TypeError("Expected argument 'work_request_ids' to be a list")
        pulumi.set(__self__, "work_request_ids", work_request_ids)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

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
        Task identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="monitoredResourceTaskId")
    def monitored_resource_task_id(self) -> str:
        return pulumi.get(self, "monitored_resource_task_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        Name of the task.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the stack monitoring resource task.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="taskDetails")
    def task_details(self) -> Sequence['outputs.GetMonitoredResourceTaskTaskDetailResult']:
        """
        The request details for the performing the task.
        """
        return pulumi.get(self, "task_details")

    @property
    @pulumi.getter(name="tenantId")
    def tenant_id(self) -> str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
        """
        return pulumi.get(self, "tenant_id")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter(name="workRequestIds")
    def work_request_ids(self) -> Sequence[str]:
        """
        Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
        """
        return pulumi.get(self, "work_request_ids")


class AwaitableGetMonitoredResourceTaskResult(GetMonitoredResourceTaskResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMonitoredResourceTaskResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            freeform_tags=self.freeform_tags,
            id=self.id,
            monitored_resource_task_id=self.monitored_resource_task_id,
            name=self.name,
            state=self.state,
            system_tags=self.system_tags,
            task_details=self.task_details,
            tenant_id=self.tenant_id,
            time_created=self.time_created,
            time_updated=self.time_updated,
            work_request_ids=self.work_request_ids)


def get_monitored_resource_task(monitored_resource_task_id: Optional[str] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMonitoredResourceTaskResult:
    """
    This data source provides details about a specific Monitored Resource Task resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets stack monitoring resource task details by identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitored_resource_task = oci.StackMonitoring.get_monitored_resource_task(monitored_resource_task_id=oci_stack_monitoring_monitored_resource_task["test_monitored_resource_task"]["id"])
    ```


    :param str monitored_resource_task_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of stack monitoring resource task.
    """
    __args__ = dict()
    __args__['monitoredResourceTaskId'] = monitored_resource_task_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:StackMonitoring/getMonitoredResourceTask:getMonitoredResourceTask', __args__, opts=opts, typ=GetMonitoredResourceTaskResult).value

    return AwaitableGetMonitoredResourceTaskResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        monitored_resource_task_id=pulumi.get(__ret__, 'monitored_resource_task_id'),
        name=pulumi.get(__ret__, 'name'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        task_details=pulumi.get(__ret__, 'task_details'),
        tenant_id=pulumi.get(__ret__, 'tenant_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'),
        work_request_ids=pulumi.get(__ret__, 'work_request_ids'))


@_utilities.lift_output_func(get_monitored_resource_task)
def get_monitored_resource_task_output(monitored_resource_task_id: Optional[pulumi.Input[str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetMonitoredResourceTaskResult]:
    """
    This data source provides details about a specific Monitored Resource Task resource in Oracle Cloud Infrastructure Stack Monitoring service.

    Gets stack monitoring resource task details by identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_monitored_resource_task = oci.StackMonitoring.get_monitored_resource_task(monitored_resource_task_id=oci_stack_monitoring_monitored_resource_task["test_monitored_resource_task"]["id"])
    ```


    :param str monitored_resource_task_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of stack monitoring resource task.
    """
    ...