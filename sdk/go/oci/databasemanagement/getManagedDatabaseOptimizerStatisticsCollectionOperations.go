// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed Database Optimizer Statistics Collection Operations in Oracle Cloud Infrastructure Database Management service.
//
// Lists the optimizer statistics (Auto and Manual) task operation summary for the specified Managed Database.
// The summary includes the details of each operation and the number of tasks grouped by status: Completed, In Progress, Failed, and so on.
// Optionally, you can specify a date-time range (of seven days) to obtain the list of operations that fall within the specified time range.
// If the date-time range is not specified, then the operations in the last seven days are listed.
// This API also enables the pagination of results and the opc-next-page response header indicates whether there is a next page.
// If you use the same header value in a consecutive request, the next page records are returned.
// To obtain the required results, you can apply the different types of filters supported by this API.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.GetManagedDatabaseOptimizerStatisticsCollectionOperations(ctx, &databasemanagement.GetManagedDatabaseOptimizerStatisticsCollectionOperationsArgs{
//				ManagedDatabaseId:             testManagedDatabase.Id,
//				EndTimeLessThanOrEqualTo:      pulumi.StringRef(managedDatabaseOptimizerStatisticsCollectionOperationEndTimeLessThanOrEqualTo),
//				FilterBy:                      pulumi.StringRef(managedDatabaseOptimizerStatisticsCollectionOperationFilterBy),
//				StartTimeGreaterThanOrEqualTo: pulumi.StringRef(managedDatabaseOptimizerStatisticsCollectionOperationStartTimeGreaterThanOrEqualTo),
//				TaskType:                      pulumi.StringRef(managedDatabaseOptimizerStatisticsCollectionOperationTaskType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseOptimizerStatisticsCollectionOperations(ctx *pulumi.Context, args *GetManagedDatabaseOptimizerStatisticsCollectionOperationsArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionOperations:getManagedDatabaseOptimizerStatisticsCollectionOperations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseOptimizerStatisticsCollectionOperations.
type GetManagedDatabaseOptimizerStatisticsCollectionOperationsArgs struct {
	// The end time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
	EndTimeLessThanOrEqualTo *string `pulumi:"endTimeLessThanOrEqualTo"`
	// The parameter used to filter the optimizer statistics operations. Any property of the OptimizerStatisticsCollectionOperationSummary can be used to define the filter condition. The allowed conditional operators are AND or OR, and the allowed binary operators are are >, < and =. Any other operator is regarded invalid. Example: jobName=<replace with job name> AND status=<replace with status>
	FilterBy *string                                                           `pulumi:"filterBy"`
	Filters  []GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilter `pulumi:"filters"`
	Limit    *int                                                              `pulumi:"limit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The start time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
	StartTimeGreaterThanOrEqualTo *string `pulumi:"startTimeGreaterThanOrEqualTo"`
	// The filter types of the optimizer statistics tasks.
	TaskType *string `pulumi:"taskType"`
}

// A collection of values returned by getManagedDatabaseOptimizerStatisticsCollectionOperations.
type GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult struct {
	EndTimeLessThanOrEqualTo *string                                                           `pulumi:"endTimeLessThanOrEqualTo"`
	FilterBy                 *string                                                           `pulumi:"filterBy"`
	Filters                  []GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                string `pulumi:"id"`
	Limit             *int   `pulumi:"limit"`
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The list of optimizer_statistics_collection_operations_collection.
	OptimizerStatisticsCollectionOperationsCollections []GetManagedDatabaseOptimizerStatisticsCollectionOperationsOptimizerStatisticsCollectionOperationsCollection `pulumi:"optimizerStatisticsCollectionOperationsCollections"`
	StartTimeGreaterThanOrEqualTo                      *string                                                                                                      `pulumi:"startTimeGreaterThanOrEqualTo"`
	TaskType                                           *string                                                                                                      `pulumi:"taskType"`
}

func GetManagedDatabaseOptimizerStatisticsCollectionOperationsOutput(ctx *pulumi.Context, args GetManagedDatabaseOptimizerStatisticsCollectionOperationsOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput, error) {
			args := v.(GetManagedDatabaseOptimizerStatisticsCollectionOperationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getManagedDatabaseOptimizerStatisticsCollectionOperations:getManagedDatabaseOptimizerStatisticsCollectionOperations", args, GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput{}, options).(GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput), nil
		}).(GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseOptimizerStatisticsCollectionOperations.
type GetManagedDatabaseOptimizerStatisticsCollectionOperationsOutputArgs struct {
	// The end time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
	EndTimeLessThanOrEqualTo pulumi.StringPtrInput `pulumi:"endTimeLessThanOrEqualTo"`
	// The parameter used to filter the optimizer statistics operations. Any property of the OptimizerStatisticsCollectionOperationSummary can be used to define the filter condition. The allowed conditional operators are AND or OR, and the allowed binary operators are are >, < and =. Any other operator is regarded invalid. Example: jobName=<replace with job name> AND status=<replace with status>
	FilterBy pulumi.StringPtrInput                                                     `pulumi:"filterBy"`
	Filters  GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilterArrayInput `pulumi:"filters"`
	Limit    pulumi.IntPtrInput                                                        `pulumi:"limit"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
	// The start time of the time range to retrieve the optimizer statistics of a Managed Database in UTC in ISO-8601 format, which is "yyyy-MM-dd'T'hh:mm:ss.sss'Z'".
	StartTimeGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"startTimeGreaterThanOrEqualTo"`
	// The filter types of the optimizer statistics tasks.
	TaskType pulumi.StringPtrInput `pulumi:"taskType"`
}

func (GetManagedDatabaseOptimizerStatisticsCollectionOperationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseOptimizerStatisticsCollectionOperationsArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseOptimizerStatisticsCollectionOperations.
type GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult)(nil)).Elem()
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) ToGetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput() GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput {
	return o
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) ToGetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutputWithContext(ctx context.Context) GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput {
	return o
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) EndTimeLessThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) *string {
		return v.EndTimeLessThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) FilterBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) *string { return v.FilterBy }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) Filters() GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilterArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) []GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilter {
		return v.Filters
	}).(GetManagedDatabaseOptimizerStatisticsCollectionOperationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) Limit() pulumi.IntPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) *int { return v.Limit }).(pulumi.IntPtrOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) string {
		return v.ManagedDatabaseId
	}).(pulumi.StringOutput)
}

// The list of optimizer_statistics_collection_operations_collection.
func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) OptimizerStatisticsCollectionOperationsCollections() GetManagedDatabaseOptimizerStatisticsCollectionOperationsOptimizerStatisticsCollectionOperationsCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) []GetManagedDatabaseOptimizerStatisticsCollectionOperationsOptimizerStatisticsCollectionOperationsCollection {
		return v.OptimizerStatisticsCollectionOperationsCollections
	}).(GetManagedDatabaseOptimizerStatisticsCollectionOperationsOptimizerStatisticsCollectionOperationsCollectionArrayOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) StartTimeGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) *string {
		return v.StartTimeGreaterThanOrEqualTo
	}).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput) TaskType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseOptimizerStatisticsCollectionOperationsResult) *string { return v.TaskType }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseOptimizerStatisticsCollectionOperationsResultOutput{})
}
