// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Database Sql Tuning Advisor Tasks Summary Report resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the summary report for the specified SQL Tuning Advisor task.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DatabaseManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DatabaseManagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReport(ctx, &databasemanagement.GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs{
//				ManagedDatabaseId:               oci_database_management_managed_database.Test_managed_database.Id,
//				SqlTuningAdvisorTaskId:          oci_database_management_sql_tuning_advisor_task.Test_sql_tuning_advisor_task.Id,
//				BeginExecIdGreaterThanOrEqualTo: pulumi.StringRef(_var.Managed_database_sql_tuning_advisor_tasks_summary_report_begin_exec_id_greater_than_or_equal_to),
//				EndExecIdLessThanOrEqualTo:      pulumi.StringRef(_var.Managed_database_sql_tuning_advisor_tasks_summary_report_end_exec_id_less_than_or_equal_to),
//				SearchPeriod:                    pulumi.StringRef(_var.Managed_database_sql_tuning_advisor_tasks_summary_report_search_period),
//				TimeGreaterThanOrEqualTo:        pulumi.StringRef(_var.Managed_database_sql_tuning_advisor_tasks_summary_report_time_greater_than_or_equal_to),
//				TimeLessThanOrEqualTo:           pulumi.StringRef(_var.Managed_database_sql_tuning_advisor_tasks_summary_report_time_less_than_or_equal_to),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseSqlTuningAdvisorTasksSummaryReport(ctx *pulumi.Context, args *GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult, error) {
	var rv GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseSqlTuningAdvisorTasksSummaryReport:getManagedDatabaseSqlTuningAdvisorTasksSummaryReport", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
type GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs struct {
	// The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
	BeginExecIdGreaterThanOrEqualTo *string `pulumi:"beginExecIdGreaterThanOrEqualTo"`
	// The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
	EndExecIdLessThanOrEqualTo *string `pulumi:"endExecIdLessThanOrEqualTo"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
	SearchPeriod *string `pulumi:"searchPeriod"`
	// The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SqlTuningAdvisorTaskId string `pulumi:"sqlTuningAdvisorTaskId"`
	// The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
	TimeGreaterThanOrEqualTo *string `pulumi:"timeGreaterThanOrEqualTo"`
	// The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
	TimeLessThanOrEqualTo *string `pulumi:"timeLessThanOrEqualTo"`
}

// A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
type GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult struct {
	BeginExecIdGreaterThanOrEqualTo *string `pulumi:"beginExecIdGreaterThanOrEqualTo"`
	EndExecIdLessThanOrEqualTo      *string `pulumi:"endExecIdLessThanOrEqualTo"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of object findings related to indexes.
	IndexFindings     []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding `pulumi:"indexFindings"`
	ManagedDatabaseId string                                                             `pulumi:"managedDatabaseId"`
	// The list of object findings related to statistics.
	ObjectStatFindings     []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding `pulumi:"objectStatFindings"`
	SearchPeriod           *string                                                                 `pulumi:"searchPeriod"`
	SqlTuningAdvisorTaskId string                                                                  `pulumi:"sqlTuningAdvisorTaskId"`
	// The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
	Statistics []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic `pulumi:"statistics"`
	// The general information regarding the SQL Tuning Advisor task.
	TaskInfos                []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo `pulumi:"taskInfos"`
	TimeGreaterThanOrEqualTo *string                                                        `pulumi:"timeGreaterThanOrEqualTo"`
	TimeLessThanOrEqualTo    *string                                                        `pulumi:"timeLessThanOrEqualTo"`
}

func GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutput(ctx *pulumi.Context, args GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult, error) {
			args := v.(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs)
			r, err := GetManagedDatabaseSqlTuningAdvisorTasksSummaryReport(ctx, &args, opts...)
			var s GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
type GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutputArgs struct {
	// The optional greater than or equal to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
	BeginExecIdGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"beginExecIdGreaterThanOrEqualTo"`
	// The optional less than or equal to query parameter to filter on the execution ID related to a specific SQL Tuning Advisor task. This is applicable only for Auto SQL Tuning tasks.
	EndExecIdLessThanOrEqualTo pulumi.StringPtrInput `pulumi:"endExecIdLessThanOrEqualTo"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
	// How far back the API will search for begin and end exec id. Unused if neither exec ids nor time filter query params are supplied. This is applicable only for Auto SQL Tuning tasks.
	SearchPeriod pulumi.StringPtrInput `pulumi:"searchPeriod"`
	// The SQL tuning task identifier. This is not the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	SqlTuningAdvisorTaskId pulumi.StringInput `pulumi:"sqlTuningAdvisorTaskId"`
	// The optional greater than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
	TimeGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeGreaterThanOrEqualTo"`
	// The optional less than or equal to query parameter to filter the timestamp. This is applicable only for Auto SQL Tuning tasks.
	TimeLessThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeLessThanOrEqualTo"`
}

func (GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseSqlTuningAdvisorTasksSummaryReport.
type GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult)(nil)).Elem()
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) ToGetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput() GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput {
	return o
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) ToGetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutputWithContext(ctx context.Context) GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput {
	return o
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) BeginExecIdGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) *string {
		return v.BeginExecIdGreaterThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) EndExecIdLessThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) *string {
		return v.EndExecIdLessThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of object findings related to indexes.
func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) IndexFindings() GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFindingArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFinding {
		return v.IndexFindings
	}).(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportIndexFindingArrayOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// The list of object findings related to statistics.
func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) ObjectStatFindings() GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFindingArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFinding {
		return v.ObjectStatFindings
	}).(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportObjectStatFindingArrayOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) SearchPeriod() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) *string { return v.SearchPeriod }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) SqlTuningAdvisorTaskId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) string {
		return v.SqlTuningAdvisorTaskId
	}).(pulumi.StringOutput)
}

// The number of distinct SQL statements with stale or missing optimizer statistics recommendations.
func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) Statistics() GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatistic {
		return v.Statistics
	}).(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportStatisticArrayOutput)
}

// The general information regarding the SQL Tuning Advisor task.
func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) TaskInfos() GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfoArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) []GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfo {
		return v.TaskInfos
	}).(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportTaskInfoArrayOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) TimeGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) *string {
		return v.TimeGreaterThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput) TimeLessThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResult) *string {
		return v.TimeLessThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseSqlTuningAdvisorTasksSummaryReportResultOutput{})
}