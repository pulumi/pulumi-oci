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
    'GetManagedDatabaseOptimizerStatisticsCollectionOperationResult',
    'AwaitableGetManagedDatabaseOptimizerStatisticsCollectionOperationResult',
    'get_managed_database_optimizer_statistics_collection_operation',
    'get_managed_database_optimizer_statistics_collection_operation_output',
]

@pulumi.output_type
class GetManagedDatabaseOptimizerStatisticsCollectionOperationResult:
    """
    A collection of values returned by getManagedDatabaseOptimizerStatisticsCollectionOperation.
    """
    def __init__(__self__, completed_count=None, databases=None, duration_in_seconds=None, end_time=None, failed_count=None, id=None, in_progress_count=None, job_name=None, managed_database_id=None, operation_name=None, optimizer_statistics_collection_operation_id=None, start_time=None, status=None, target=None, tasks=None, timed_out_count=None, total_objects_count=None):
        if completed_count and not isinstance(completed_count, int):
            raise TypeError("Expected argument 'completed_count' to be a int")
        pulumi.set(__self__, "completed_count", completed_count)
        if databases and not isinstance(databases, list):
            raise TypeError("Expected argument 'databases' to be a list")
        pulumi.set(__self__, "databases", databases)
        if duration_in_seconds and not isinstance(duration_in_seconds, float):
            raise TypeError("Expected argument 'duration_in_seconds' to be a float")
        pulumi.set(__self__, "duration_in_seconds", duration_in_seconds)
        if end_time and not isinstance(end_time, str):
            raise TypeError("Expected argument 'end_time' to be a str")
        pulumi.set(__self__, "end_time", end_time)
        if failed_count and not isinstance(failed_count, int):
            raise TypeError("Expected argument 'failed_count' to be a int")
        pulumi.set(__self__, "failed_count", failed_count)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if in_progress_count and not isinstance(in_progress_count, int):
            raise TypeError("Expected argument 'in_progress_count' to be a int")
        pulumi.set(__self__, "in_progress_count", in_progress_count)
        if job_name and not isinstance(job_name, str):
            raise TypeError("Expected argument 'job_name' to be a str")
        pulumi.set(__self__, "job_name", job_name)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if operation_name and not isinstance(operation_name, str):
            raise TypeError("Expected argument 'operation_name' to be a str")
        pulumi.set(__self__, "operation_name", operation_name)
        if optimizer_statistics_collection_operation_id and not isinstance(optimizer_statistics_collection_operation_id, float):
            raise TypeError("Expected argument 'optimizer_statistics_collection_operation_id' to be a float")
        pulumi.set(__self__, "optimizer_statistics_collection_operation_id", optimizer_statistics_collection_operation_id)
        if start_time and not isinstance(start_time, str):
            raise TypeError("Expected argument 'start_time' to be a str")
        pulumi.set(__self__, "start_time", start_time)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if target and not isinstance(target, str):
            raise TypeError("Expected argument 'target' to be a str")
        pulumi.set(__self__, "target", target)
        if tasks and not isinstance(tasks, list):
            raise TypeError("Expected argument 'tasks' to be a list")
        pulumi.set(__self__, "tasks", tasks)
        if timed_out_count and not isinstance(timed_out_count, int):
            raise TypeError("Expected argument 'timed_out_count' to be a int")
        pulumi.set(__self__, "timed_out_count", timed_out_count)
        if total_objects_count and not isinstance(total_objects_count, int):
            raise TypeError("Expected argument 'total_objects_count' to be a int")
        pulumi.set(__self__, "total_objects_count", total_objects_count)

    @property
    @pulumi.getter(name="completedCount")
    def completed_count(self) -> int:
        """
        The number of objects for which statistics collection is completed.
        """
        return pulumi.get(self, "completed_count")

    @property
    @pulumi.getter
    def databases(self) -> Sequence['outputs.GetManagedDatabaseOptimizerStatisticsCollectionOperationDatabaseResult']:
        """
        The summary of the Managed Database resource.
        """
        return pulumi.get(self, "databases")

    @property
    @pulumi.getter(name="durationInSeconds")
    def duration_in_seconds(self) -> float:
        """
        The time it takes to complete the operation (in seconds).
        """
        return pulumi.get(self, "duration_in_seconds")

    @property
    @pulumi.getter(name="endTime")
    def end_time(self) -> str:
        """
        The end time of the operation.
        """
        return pulumi.get(self, "end_time")

    @property
    @pulumi.getter(name="failedCount")
    def failed_count(self) -> int:
        """
        The number of objects for which statistics collection failed.
        """
        return pulumi.get(self, "failed_count")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="inProgressCount")
    def in_progress_count(self) -> int:
        """
        The number of objects for which statistics collection is in progress.
        """
        return pulumi.get(self, "in_progress_count")

    @property
    @pulumi.getter(name="jobName")
    def job_name(self) -> str:
        """
        The name of the job.
        """
        return pulumi.get(self, "job_name")

    @property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> str:
        return pulumi.get(self, "managed_database_id")

    @property
    @pulumi.getter(name="operationName")
    def operation_name(self) -> str:
        """
        The name of the operation.
        """
        return pulumi.get(self, "operation_name")

    @property
    @pulumi.getter(name="optimizerStatisticsCollectionOperationId")
    def optimizer_statistics_collection_operation_id(self) -> float:
        return pulumi.get(self, "optimizer_statistics_collection_operation_id")

    @property
    @pulumi.getter(name="startTime")
    def start_time(self) -> str:
        """
        The start time of the operation.
        """
        return pulumi.get(self, "start_time")

    @property
    @pulumi.getter
    def status(self) -> str:
        """
        The status of the Optimizer Statistics Collection task.
        """
        return pulumi.get(self, "status")

    @property
    @pulumi.getter
    def target(self) -> str:
        """
        The name of the target object for which statistics are gathered.
        """
        return pulumi.get(self, "target")

    @property
    @pulumi.getter
    def tasks(self) -> Sequence['outputs.GetManagedDatabaseOptimizerStatisticsCollectionOperationTaskResult']:
        """
        An array of Optimizer Statistics Collection task details.
        """
        return pulumi.get(self, "tasks")

    @property
    @pulumi.getter(name="timedOutCount")
    def timed_out_count(self) -> int:
        """
        The number of objects for which statistics collection timed out.
        """
        return pulumi.get(self, "timed_out_count")

    @property
    @pulumi.getter(name="totalObjectsCount")
    def total_objects_count(self) -> int:
        """
        The total number of objects for which statistics is collected. This number is the sum of all the objects with various statuses: completed, inProgress, failed, and timedOut.
        """
        return pulumi.get(self, "total_objects_count")


class AwaitableGetManagedDatabaseOptimizerStatisticsCollectionOperationResult(GetManagedDatabaseOptimizerStatisticsCollectionOperationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseOptimizerStatisticsCollectionOperationResult(
            completed_count=self.completed_count,
            databases=self.databases,
            duration_in_seconds=self.duration_in_seconds,
            end_time=self.end_time,
            failed_count=self.failed_count,
            id=self.id,
            in_progress_count=self.in_progress_count,
            job_name=self.job_name,
            managed_database_id=self.managed_database_id,
            operation_name=self.operation_name,
            optimizer_statistics_collection_operation_id=self.optimizer_statistics_collection_operation_id,
            start_time=self.start_time,
            status=self.status,
            target=self.target,
            tasks=self.tasks,
            timed_out_count=self.timed_out_count,
            total_objects_count=self.total_objects_count)


def get_managed_database_optimizer_statistics_collection_operation(managed_database_id: Optional[str] = None,
                                                                   optimizer_statistics_collection_operation_id: Optional[float] = None,
                                                                   opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseOptimizerStatisticsCollectionOperationResult:
    """
    This data source provides details about a specific Managed Database Optimizer Statistics Collection Operation resource in Oracle Cloud Infrastructure Database Management service.

    Gets a detailed report of the Optimizer Statistics Collection operation for the specified Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_optimizer_statistics_collection_operation = oci.DatabaseManagement.get_managed_database_optimizer_statistics_collection_operation(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        optimizer_statistics_collection_operation_id=oci_database_management_optimizer_statistics_collection_operation["test_optimizer_statistics_collection_operation"]["id"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param float optimizer_statistics_collection_operation_id: The ID of the Optimizer Statistics Collection operation.
    """
    __args__ = dict()
    __args__['managedDatabaseId'] = managed_database_id
    __args__['optimizerStatisticsCollectionOperationId'] = optimizer_statistics_collection_operation_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionOperation:getManagedDatabaseOptimizerStatisticsCollectionOperation', __args__, opts=opts, typ=GetManagedDatabaseOptimizerStatisticsCollectionOperationResult).value

    return AwaitableGetManagedDatabaseOptimizerStatisticsCollectionOperationResult(
        completed_count=__ret__.completed_count,
        databases=__ret__.databases,
        duration_in_seconds=__ret__.duration_in_seconds,
        end_time=__ret__.end_time,
        failed_count=__ret__.failed_count,
        id=__ret__.id,
        in_progress_count=__ret__.in_progress_count,
        job_name=__ret__.job_name,
        managed_database_id=__ret__.managed_database_id,
        operation_name=__ret__.operation_name,
        optimizer_statistics_collection_operation_id=__ret__.optimizer_statistics_collection_operation_id,
        start_time=__ret__.start_time,
        status=__ret__.status,
        target=__ret__.target,
        tasks=__ret__.tasks,
        timed_out_count=__ret__.timed_out_count,
        total_objects_count=__ret__.total_objects_count)


@_utilities.lift_output_func(get_managed_database_optimizer_statistics_collection_operation)
def get_managed_database_optimizer_statistics_collection_operation_output(managed_database_id: Optional[pulumi.Input[str]] = None,
                                                                          optimizer_statistics_collection_operation_id: Optional[pulumi.Input[float]] = None,
                                                                          opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetManagedDatabaseOptimizerStatisticsCollectionOperationResult]:
    """
    This data source provides details about a specific Managed Database Optimizer Statistics Collection Operation resource in Oracle Cloud Infrastructure Database Management service.

    Gets a detailed report of the Optimizer Statistics Collection operation for the specified Managed Database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_optimizer_statistics_collection_operation = oci.DatabaseManagement.get_managed_database_optimizer_statistics_collection_operation(managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        optimizer_statistics_collection_operation_id=oci_database_management_optimizer_statistics_collection_operation["test_optimizer_statistics_collection_operation"]["id"])
    ```


    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param float optimizer_statistics_collection_operation_id: The ID of the Optimizer Statistics Collection operation.
    """
    ...