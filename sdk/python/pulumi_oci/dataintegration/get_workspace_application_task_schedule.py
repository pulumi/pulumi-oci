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
    'GetWorkspaceApplicationTaskScheduleResult',
    'AwaitableGetWorkspaceApplicationTaskScheduleResult',
    'get_workspace_application_task_schedule',
    'get_workspace_application_task_schedule_output',
]

@pulumi.output_type
class GetWorkspaceApplicationTaskScheduleResult:
    """
    A collection of values returned by getWorkspaceApplicationTaskSchedule.
    """
    def __init__(__self__, application_key=None, auth_mode=None, config_provider_delegate=None, description=None, end_time_millis=None, expected_duration=None, expected_duration_unit=None, id=None, identifier=None, is_backfill_enabled=None, is_concurrent_allowed=None, is_enabled=None, key=None, last_run_details=None, metadatas=None, model_type=None, model_version=None, name=None, next_run_time_millis=None, number_of_retries=None, object_status=None, object_version=None, parent_reves=None, registry_metadatas=None, retry_attempts=None, retry_delay=None, retry_delay_unit=None, schedule_reves=None, start_time_millis=None, task_schedule_key=None, workspace_id=None):
        if application_key and not isinstance(application_key, str):
            raise TypeError("Expected argument 'application_key' to be a str")
        pulumi.set(__self__, "application_key", application_key)
        if auth_mode and not isinstance(auth_mode, str):
            raise TypeError("Expected argument 'auth_mode' to be a str")
        pulumi.set(__self__, "auth_mode", auth_mode)
        if config_provider_delegate and not isinstance(config_provider_delegate, str):
            raise TypeError("Expected argument 'config_provider_delegate' to be a str")
        pulumi.set(__self__, "config_provider_delegate", config_provider_delegate)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if end_time_millis and not isinstance(end_time_millis, str):
            raise TypeError("Expected argument 'end_time_millis' to be a str")
        pulumi.set(__self__, "end_time_millis", end_time_millis)
        if expected_duration and not isinstance(expected_duration, float):
            raise TypeError("Expected argument 'expected_duration' to be a float")
        pulumi.set(__self__, "expected_duration", expected_duration)
        if expected_duration_unit and not isinstance(expected_duration_unit, str):
            raise TypeError("Expected argument 'expected_duration_unit' to be a str")
        pulumi.set(__self__, "expected_duration_unit", expected_duration_unit)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if identifier and not isinstance(identifier, str):
            raise TypeError("Expected argument 'identifier' to be a str")
        pulumi.set(__self__, "identifier", identifier)
        if is_backfill_enabled and not isinstance(is_backfill_enabled, bool):
            raise TypeError("Expected argument 'is_backfill_enabled' to be a bool")
        pulumi.set(__self__, "is_backfill_enabled", is_backfill_enabled)
        if is_concurrent_allowed and not isinstance(is_concurrent_allowed, bool):
            raise TypeError("Expected argument 'is_concurrent_allowed' to be a bool")
        pulumi.set(__self__, "is_concurrent_allowed", is_concurrent_allowed)
        if is_enabled and not isinstance(is_enabled, bool):
            raise TypeError("Expected argument 'is_enabled' to be a bool")
        pulumi.set(__self__, "is_enabled", is_enabled)
        if key and not isinstance(key, str):
            raise TypeError("Expected argument 'key' to be a str")
        pulumi.set(__self__, "key", key)
        if last_run_details and not isinstance(last_run_details, list):
            raise TypeError("Expected argument 'last_run_details' to be a list")
        pulumi.set(__self__, "last_run_details", last_run_details)
        if metadatas and not isinstance(metadatas, list):
            raise TypeError("Expected argument 'metadatas' to be a list")
        pulumi.set(__self__, "metadatas", metadatas)
        if model_type and not isinstance(model_type, str):
            raise TypeError("Expected argument 'model_type' to be a str")
        pulumi.set(__self__, "model_type", model_type)
        if model_version and not isinstance(model_version, str):
            raise TypeError("Expected argument 'model_version' to be a str")
        pulumi.set(__self__, "model_version", model_version)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if next_run_time_millis and not isinstance(next_run_time_millis, str):
            raise TypeError("Expected argument 'next_run_time_millis' to be a str")
        pulumi.set(__self__, "next_run_time_millis", next_run_time_millis)
        if number_of_retries and not isinstance(number_of_retries, int):
            raise TypeError("Expected argument 'number_of_retries' to be a int")
        pulumi.set(__self__, "number_of_retries", number_of_retries)
        if object_status and not isinstance(object_status, int):
            raise TypeError("Expected argument 'object_status' to be a int")
        pulumi.set(__self__, "object_status", object_status)
        if object_version and not isinstance(object_version, int):
            raise TypeError("Expected argument 'object_version' to be a int")
        pulumi.set(__self__, "object_version", object_version)
        if parent_reves and not isinstance(parent_reves, list):
            raise TypeError("Expected argument 'parent_reves' to be a list")
        pulumi.set(__self__, "parent_reves", parent_reves)
        if registry_metadatas and not isinstance(registry_metadatas, list):
            raise TypeError("Expected argument 'registry_metadatas' to be a list")
        pulumi.set(__self__, "registry_metadatas", registry_metadatas)
        if retry_attempts and not isinstance(retry_attempts, int):
            raise TypeError("Expected argument 'retry_attempts' to be a int")
        pulumi.set(__self__, "retry_attempts", retry_attempts)
        if retry_delay and not isinstance(retry_delay, float):
            raise TypeError("Expected argument 'retry_delay' to be a float")
        pulumi.set(__self__, "retry_delay", retry_delay)
        if retry_delay_unit and not isinstance(retry_delay_unit, str):
            raise TypeError("Expected argument 'retry_delay_unit' to be a str")
        pulumi.set(__self__, "retry_delay_unit", retry_delay_unit)
        if schedule_reves and not isinstance(schedule_reves, list):
            raise TypeError("Expected argument 'schedule_reves' to be a list")
        pulumi.set(__self__, "schedule_reves", schedule_reves)
        if start_time_millis and not isinstance(start_time_millis, str):
            raise TypeError("Expected argument 'start_time_millis' to be a str")
        pulumi.set(__self__, "start_time_millis", start_time_millis)
        if task_schedule_key and not isinstance(task_schedule_key, str):
            raise TypeError("Expected argument 'task_schedule_key' to be a str")
        pulumi.set(__self__, "task_schedule_key", task_schedule_key)
        if workspace_id and not isinstance(workspace_id, str):
            raise TypeError("Expected argument 'workspace_id' to be a str")
        pulumi.set(__self__, "workspace_id", workspace_id)

    @_builtins.property
    @pulumi.getter(name="applicationKey")
    def application_key(self) -> _builtins.str:
        return pulumi.get(self, "application_key")

    @_builtins.property
    @pulumi.getter(name="authMode")
    def auth_mode(self) -> _builtins.str:
        """
        The authorization mode for the task.
        """
        return pulumi.get(self, "auth_mode")

    @_builtins.property
    @pulumi.getter(name="configProviderDelegate")
    def config_provider_delegate(self) -> _builtins.str:
        return pulumi.get(self, "config_provider_delegate")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The description of the aggregator.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="endTimeMillis")
    def end_time_millis(self) -> _builtins.str:
        """
        The end time in milliseconds.
        """
        return pulumi.get(self, "end_time_millis")

    @_builtins.property
    @pulumi.getter(name="expectedDuration")
    def expected_duration(self) -> _builtins.float:
        """
        The expected duration of the task execution.
        """
        return pulumi.get(self, "expected_duration")

    @_builtins.property
    @pulumi.getter(name="expectedDurationUnit")
    def expected_duration_unit(self) -> _builtins.str:
        """
        The expected duration unit of the task execution.
        """
        return pulumi.get(self, "expected_duration_unit")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def identifier(self) -> _builtins.str:
        """
        The identifier of the aggregator.
        """
        return pulumi.get(self, "identifier")

    @_builtins.property
    @pulumi.getter(name="isBackfillEnabled")
    def is_backfill_enabled(self) -> _builtins.bool:
        """
        Whether the backfill is enabled
        """
        return pulumi.get(self, "is_backfill_enabled")

    @_builtins.property
    @pulumi.getter(name="isConcurrentAllowed")
    def is_concurrent_allowed(self) -> _builtins.bool:
        """
        Whether the same task can be executed concurrently.
        """
        return pulumi.get(self, "is_concurrent_allowed")

    @_builtins.property
    @pulumi.getter(name="isEnabled")
    def is_enabled(self) -> _builtins.bool:
        """
        Whether the schedule is enabled.
        """
        return pulumi.get(self, "is_enabled")

    @_builtins.property
    @pulumi.getter
    def key(self) -> _builtins.str:
        """
        The key of the aggregator object.
        """
        return pulumi.get(self, "key")

    @_builtins.property
    @pulumi.getter(name="lastRunDetails")
    def last_run_details(self) -> Sequence['outputs.GetWorkspaceApplicationTaskScheduleLastRunDetailResult']:
        """
        The last run details for the task run.
        """
        return pulumi.get(self, "last_run_details")

    @_builtins.property
    @pulumi.getter
    def metadatas(self) -> Sequence['outputs.GetWorkspaceApplicationTaskScheduleMetadataResult']:
        """
        A summary type containing information about the object including its key, name and when/who created/updated it.
        """
        return pulumi.get(self, "metadatas")

    @_builtins.property
    @pulumi.getter(name="modelType")
    def model_type(self) -> _builtins.str:
        """
        The type of the object.
        """
        return pulumi.get(self, "model_type")

    @_builtins.property
    @pulumi.getter(name="modelVersion")
    def model_version(self) -> _builtins.str:
        """
        This is a version number that is used by the service to upgrade objects if needed through releases of the service.
        """
        return pulumi.get(self, "model_version")

    @_builtins.property
    @pulumi.getter
    def name(self) -> _builtins.str:
        """
        Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        """
        return pulumi.get(self, "name")

    @_builtins.property
    @pulumi.getter(name="nextRunTimeMillis")
    def next_run_time_millis(self) -> _builtins.str:
        return pulumi.get(self, "next_run_time_millis")

    @_builtins.property
    @pulumi.getter(name="numberOfRetries")
    def number_of_retries(self) -> _builtins.int:
        return pulumi.get(self, "number_of_retries")

    @_builtins.property
    @pulumi.getter(name="objectStatus")
    def object_status(self) -> _builtins.int:
        """
        The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        """
        return pulumi.get(self, "object_status")

    @_builtins.property
    @pulumi.getter(name="objectVersion")
    def object_version(self) -> _builtins.int:
        """
        This is used by the service for optimistic locking of the object, to prevent multiple users from simultaneously updating the object.
        """
        return pulumi.get(self, "object_version")

    @_builtins.property
    @pulumi.getter(name="parentReves")
    def parent_reves(self) -> Sequence['outputs.GetWorkspaceApplicationTaskScheduleParentRefResult']:
        """
        A reference to the object's parent.
        """
        return pulumi.get(self, "parent_reves")

    @_builtins.property
    @pulumi.getter(name="registryMetadatas")
    def registry_metadatas(self) -> Sequence['outputs.GetWorkspaceApplicationTaskScheduleRegistryMetadataResult']:
        return pulumi.get(self, "registry_metadatas")

    @_builtins.property
    @pulumi.getter(name="retryAttempts")
    def retry_attempts(self) -> _builtins.int:
        """
        The number of retry attempts.
        """
        return pulumi.get(self, "retry_attempts")

    @_builtins.property
    @pulumi.getter(name="retryDelay")
    def retry_delay(self) -> _builtins.float:
        """
        The retry delay, the unit for measurement is in the property retry delay unit.
        """
        return pulumi.get(self, "retry_delay")

    @_builtins.property
    @pulumi.getter(name="retryDelayUnit")
    def retry_delay_unit(self) -> _builtins.str:
        """
        The unit for the retry delay.
        """
        return pulumi.get(self, "retry_delay_unit")

    @_builtins.property
    @pulumi.getter(name="scheduleReves")
    def schedule_reves(self) -> Sequence['outputs.GetWorkspaceApplicationTaskScheduleScheduleRefResult']:
        """
        The schedule object
        """
        return pulumi.get(self, "schedule_reves")

    @_builtins.property
    @pulumi.getter(name="startTimeMillis")
    def start_time_millis(self) -> _builtins.str:
        """
        The start time in milliseconds.
        """
        return pulumi.get(self, "start_time_millis")

    @_builtins.property
    @pulumi.getter(name="taskScheduleKey")
    def task_schedule_key(self) -> _builtins.str:
        return pulumi.get(self, "task_schedule_key")

    @_builtins.property
    @pulumi.getter(name="workspaceId")
    def workspace_id(self) -> _builtins.str:
        return pulumi.get(self, "workspace_id")


class AwaitableGetWorkspaceApplicationTaskScheduleResult(GetWorkspaceApplicationTaskScheduleResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetWorkspaceApplicationTaskScheduleResult(
            application_key=self.application_key,
            auth_mode=self.auth_mode,
            config_provider_delegate=self.config_provider_delegate,
            description=self.description,
            end_time_millis=self.end_time_millis,
            expected_duration=self.expected_duration,
            expected_duration_unit=self.expected_duration_unit,
            id=self.id,
            identifier=self.identifier,
            is_backfill_enabled=self.is_backfill_enabled,
            is_concurrent_allowed=self.is_concurrent_allowed,
            is_enabled=self.is_enabled,
            key=self.key,
            last_run_details=self.last_run_details,
            metadatas=self.metadatas,
            model_type=self.model_type,
            model_version=self.model_version,
            name=self.name,
            next_run_time_millis=self.next_run_time_millis,
            number_of_retries=self.number_of_retries,
            object_status=self.object_status,
            object_version=self.object_version,
            parent_reves=self.parent_reves,
            registry_metadatas=self.registry_metadatas,
            retry_attempts=self.retry_attempts,
            retry_delay=self.retry_delay,
            retry_delay_unit=self.retry_delay_unit,
            schedule_reves=self.schedule_reves,
            start_time_millis=self.start_time_millis,
            task_schedule_key=self.task_schedule_key,
            workspace_id=self.workspace_id)


def get_workspace_application_task_schedule(application_key: Optional[_builtins.str] = None,
                                            task_schedule_key: Optional[_builtins.str] = None,
                                            workspace_id: Optional[_builtins.str] = None,
                                            opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetWorkspaceApplicationTaskScheduleResult:
    """
    This data source provides details about a specific Workspace Application Task Schedule resource in Oracle Cloud Infrastructure Data Integration service.

    Endpoint used to get taskSchedule by its key

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_workspace_application_task_schedule = oci.DataIntegration.get_workspace_application_task_schedule(application_key=workspace_application_task_schedule_application_key,
        task_schedule_key=workspace_application_task_schedule_task_schedule_key,
        workspace_id=test_workspace["id"])
    ```


    :param _builtins.str application_key: The application key.
    :param _builtins.str task_schedule_key: TaskSchedule Key
    :param _builtins.str workspace_id: The workspace ID.
    """
    __args__ = dict()
    __args__['applicationKey'] = application_key
    __args__['taskScheduleKey'] = task_schedule_key
    __args__['workspaceId'] = workspace_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataIntegration/getWorkspaceApplicationTaskSchedule:getWorkspaceApplicationTaskSchedule', __args__, opts=opts, typ=GetWorkspaceApplicationTaskScheduleResult).value

    return AwaitableGetWorkspaceApplicationTaskScheduleResult(
        application_key=pulumi.get(__ret__, 'application_key'),
        auth_mode=pulumi.get(__ret__, 'auth_mode'),
        config_provider_delegate=pulumi.get(__ret__, 'config_provider_delegate'),
        description=pulumi.get(__ret__, 'description'),
        end_time_millis=pulumi.get(__ret__, 'end_time_millis'),
        expected_duration=pulumi.get(__ret__, 'expected_duration'),
        expected_duration_unit=pulumi.get(__ret__, 'expected_duration_unit'),
        id=pulumi.get(__ret__, 'id'),
        identifier=pulumi.get(__ret__, 'identifier'),
        is_backfill_enabled=pulumi.get(__ret__, 'is_backfill_enabled'),
        is_concurrent_allowed=pulumi.get(__ret__, 'is_concurrent_allowed'),
        is_enabled=pulumi.get(__ret__, 'is_enabled'),
        key=pulumi.get(__ret__, 'key'),
        last_run_details=pulumi.get(__ret__, 'last_run_details'),
        metadatas=pulumi.get(__ret__, 'metadatas'),
        model_type=pulumi.get(__ret__, 'model_type'),
        model_version=pulumi.get(__ret__, 'model_version'),
        name=pulumi.get(__ret__, 'name'),
        next_run_time_millis=pulumi.get(__ret__, 'next_run_time_millis'),
        number_of_retries=pulumi.get(__ret__, 'number_of_retries'),
        object_status=pulumi.get(__ret__, 'object_status'),
        object_version=pulumi.get(__ret__, 'object_version'),
        parent_reves=pulumi.get(__ret__, 'parent_reves'),
        registry_metadatas=pulumi.get(__ret__, 'registry_metadatas'),
        retry_attempts=pulumi.get(__ret__, 'retry_attempts'),
        retry_delay=pulumi.get(__ret__, 'retry_delay'),
        retry_delay_unit=pulumi.get(__ret__, 'retry_delay_unit'),
        schedule_reves=pulumi.get(__ret__, 'schedule_reves'),
        start_time_millis=pulumi.get(__ret__, 'start_time_millis'),
        task_schedule_key=pulumi.get(__ret__, 'task_schedule_key'),
        workspace_id=pulumi.get(__ret__, 'workspace_id'))
def get_workspace_application_task_schedule_output(application_key: Optional[pulumi.Input[_builtins.str]] = None,
                                                   task_schedule_key: Optional[pulumi.Input[_builtins.str]] = None,
                                                   workspace_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                   opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetWorkspaceApplicationTaskScheduleResult]:
    """
    This data source provides details about a specific Workspace Application Task Schedule resource in Oracle Cloud Infrastructure Data Integration service.

    Endpoint used to get taskSchedule by its key

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_workspace_application_task_schedule = oci.DataIntegration.get_workspace_application_task_schedule(application_key=workspace_application_task_schedule_application_key,
        task_schedule_key=workspace_application_task_schedule_task_schedule_key,
        workspace_id=test_workspace["id"])
    ```


    :param _builtins.str application_key: The application key.
    :param _builtins.str task_schedule_key: TaskSchedule Key
    :param _builtins.str workspace_id: The workspace ID.
    """
    __args__ = dict()
    __args__['applicationKey'] = application_key
    __args__['taskScheduleKey'] = task_schedule_key
    __args__['workspaceId'] = workspace_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataIntegration/getWorkspaceApplicationTaskSchedule:getWorkspaceApplicationTaskSchedule', __args__, opts=opts, typ=GetWorkspaceApplicationTaskScheduleResult)
    return __ret__.apply(lambda __response__: GetWorkspaceApplicationTaskScheduleResult(
        application_key=pulumi.get(__response__, 'application_key'),
        auth_mode=pulumi.get(__response__, 'auth_mode'),
        config_provider_delegate=pulumi.get(__response__, 'config_provider_delegate'),
        description=pulumi.get(__response__, 'description'),
        end_time_millis=pulumi.get(__response__, 'end_time_millis'),
        expected_duration=pulumi.get(__response__, 'expected_duration'),
        expected_duration_unit=pulumi.get(__response__, 'expected_duration_unit'),
        id=pulumi.get(__response__, 'id'),
        identifier=pulumi.get(__response__, 'identifier'),
        is_backfill_enabled=pulumi.get(__response__, 'is_backfill_enabled'),
        is_concurrent_allowed=pulumi.get(__response__, 'is_concurrent_allowed'),
        is_enabled=pulumi.get(__response__, 'is_enabled'),
        key=pulumi.get(__response__, 'key'),
        last_run_details=pulumi.get(__response__, 'last_run_details'),
        metadatas=pulumi.get(__response__, 'metadatas'),
        model_type=pulumi.get(__response__, 'model_type'),
        model_version=pulumi.get(__response__, 'model_version'),
        name=pulumi.get(__response__, 'name'),
        next_run_time_millis=pulumi.get(__response__, 'next_run_time_millis'),
        number_of_retries=pulumi.get(__response__, 'number_of_retries'),
        object_status=pulumi.get(__response__, 'object_status'),
        object_version=pulumi.get(__response__, 'object_version'),
        parent_reves=pulumi.get(__response__, 'parent_reves'),
        registry_metadatas=pulumi.get(__response__, 'registry_metadatas'),
        retry_attempts=pulumi.get(__response__, 'retry_attempts'),
        retry_delay=pulumi.get(__response__, 'retry_delay'),
        retry_delay_unit=pulumi.get(__response__, 'retry_delay_unit'),
        schedule_reves=pulumi.get(__response__, 'schedule_reves'),
        start_time_millis=pulumi.get(__response__, 'start_time_millis'),
        task_schedule_key=pulumi.get(__response__, 'task_schedule_key'),
        workspace_id=pulumi.get(__response__, 'workspace_id')))
