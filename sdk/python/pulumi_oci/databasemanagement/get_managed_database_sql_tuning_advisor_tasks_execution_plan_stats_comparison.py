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
    'GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult',
    'AwaitableGetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult',
    'get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison',
    'get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison_output',
]

@pulumi.output_type
class GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult:
    """
    A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison.
    """
    def __init__(__self__, execution_id=None, id=None, managed_database_id=None, modifieds=None, originals=None, sql_object_id=None, sql_tuning_advisor_task_id=None):
        if execution_id and not isinstance(execution_id, str):
            raise TypeError("Expected argument 'execution_id' to be a str")
        pulumi.set(__self__, "execution_id", execution_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if managed_database_id and not isinstance(managed_database_id, str):
            raise TypeError("Expected argument 'managed_database_id' to be a str")
        pulumi.set(__self__, "managed_database_id", managed_database_id)
        if modifieds and not isinstance(modifieds, list):
            raise TypeError("Expected argument 'modifieds' to be a list")
        pulumi.set(__self__, "modifieds", modifieds)
        if originals and not isinstance(originals, list):
            raise TypeError("Expected argument 'originals' to be a list")
        pulumi.set(__self__, "originals", originals)
        if sql_object_id and not isinstance(sql_object_id, str):
            raise TypeError("Expected argument 'sql_object_id' to be a str")
        pulumi.set(__self__, "sql_object_id", sql_object_id)
        if sql_tuning_advisor_task_id and not isinstance(sql_tuning_advisor_task_id, str):
            raise TypeError("Expected argument 'sql_tuning_advisor_task_id' to be a str")
        pulumi.set(__self__, "sql_tuning_advisor_task_id", sql_tuning_advisor_task_id)

    @property
    @pulumi.getter(name="executionId")
    def execution_id(self) -> str:
        return pulumi.get(self, "execution_id")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="managedDatabaseId")
    def managed_database_id(self) -> str:
        return pulumi.get(self, "managed_database_id")

    @property
    @pulumi.getter
    def modifieds(self) -> Sequence['outputs.GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonModifiedResult']:
        """
        The statistics of a SQL execution plan.
        """
        return pulumi.get(self, "modifieds")

    @property
    @pulumi.getter
    def originals(self) -> Sequence['outputs.GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonOriginalResult']:
        """
        The statistics of a SQL execution plan.
        """
        return pulumi.get(self, "originals")

    @property
    @pulumi.getter(name="sqlObjectId")
    def sql_object_id(self) -> str:
        return pulumi.get(self, "sql_object_id")

    @property
    @pulumi.getter(name="sqlTuningAdvisorTaskId")
    def sql_tuning_advisor_task_id(self) -> str:
        return pulumi.get(self, "sql_tuning_advisor_task_id")


class AwaitableGetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult(GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult(
            execution_id=self.execution_id,
            id=self.id,
            managed_database_id=self.managed_database_id,
            modifieds=self.modifieds,
            originals=self.originals,
            sql_object_id=self.sql_object_id,
            sql_tuning_advisor_task_id=self.sql_tuning_advisor_task_id)


def get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison(execution_id: Optional[str] = None,
                                                                                  managed_database_id: Optional[str] = None,
                                                                                  sql_object_id: Optional[str] = None,
                                                                                  sql_tuning_advisor_task_id: Optional[str] = None,
                                                                                  opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult:
    """
    This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Execution Plan Stats Comparision resource in Oracle Cloud Infrastructure Database Management service.

    Retrieves a comparison of the existing SQL execution plan and a new plan.
    A SQL tuning task may suggest a new execution plan for a SQL,
    and this API retrieves the comparison report of the statistics of the two plans.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparision = oci.DatabaseManagement.get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison(execution_id=oci_database_management_execution["test_execution"]["id"],
        managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        sql_object_id=oci_objectstorage_object["test_object"]["id"],
        sql_tuning_advisor_task_id=oci_database_management_sql_tuning_advisor_task["test_sql_tuning_advisor_task"]["id"])
    ```


    :param str execution_id: The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str sql_object_id: The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str sql_tuning_advisor_task_id: The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['executionId'] = execution_id
    __args__['managedDatabaseId'] = managed_database_id
    __args__['sqlObjectId'] = sql_object_id
    __args__['sqlTuningAdvisorTaskId'] = sql_tuning_advisor_task_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison:getManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparison', __args__, opts=opts, typ=GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult).value

    return AwaitableGetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult(
        execution_id=__ret__.execution_id,
        id=__ret__.id,
        managed_database_id=__ret__.managed_database_id,
        modifieds=__ret__.modifieds,
        originals=__ret__.originals,
        sql_object_id=__ret__.sql_object_id,
        sql_tuning_advisor_task_id=__ret__.sql_tuning_advisor_task_id)


@_utilities.lift_output_func(get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison)
def get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison_output(execution_id: Optional[pulumi.Input[str]] = None,
                                                                                         managed_database_id: Optional[pulumi.Input[str]] = None,
                                                                                         sql_object_id: Optional[pulumi.Input[str]] = None,
                                                                                         sql_tuning_advisor_task_id: Optional[pulumi.Input[str]] = None,
                                                                                         opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisonResult]:
    """
    This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Execution Plan Stats Comparision resource in Oracle Cloud Infrastructure Database Management service.

    Retrieves a comparison of the existing SQL execution plan and a new plan.
    A SQL tuning task may suggest a new execution plan for a SQL,
    and this API retrieves the comparison report of the statistics of the two plans.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparision = oci.DatabaseManagement.get_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparison(execution_id=oci_database_management_execution["test_execution"]["id"],
        managed_database_id=oci_database_management_managed_database["test_managed_database"]["id"],
        sql_object_id=oci_objectstorage_object["test_object"]["id"],
        sql_tuning_advisor_task_id=oci_database_management_sql_tuning_advisor_task["test_sql_tuning_advisor_task"]["id"])
    ```


    :param str execution_id: The execution ID for an execution of a SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str managed_database_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
    :param str sql_object_id: The SQL object ID for the SQL tuning task. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    :param str sql_tuning_advisor_task_id: The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    ...