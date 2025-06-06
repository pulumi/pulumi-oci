// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed Database Table Statistics in Oracle Cloud Infrastructure Database Management service.
//
// Gets the number of database table objects grouped by different statuses such as
// Not Stale Stats, Stale Stats, and No Stats. This also includes the percentage of each status.
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
//			_, err := databasemanagement.GetManagedDatabaseTableStatistics(ctx, &databasemanagement.GetManagedDatabaseTableStatisticsArgs{
//				ManagedDatabaseId: testManagedDatabase.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseTableStatistics(ctx *pulumi.Context, args *GetManagedDatabaseTableStatisticsArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseTableStatisticsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagedDatabaseTableStatisticsResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseTableStatistics.
type GetManagedDatabaseTableStatisticsArgs struct {
	Filters []GetManagedDatabaseTableStatisticsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
}

// A collection of values returned by getManagedDatabaseTableStatistics.
type GetManagedDatabaseTableStatisticsResult struct {
	Filters []GetManagedDatabaseTableStatisticsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                string `pulumi:"id"`
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The list of table_statistics_collection.
	TableStatisticsCollections []GetManagedDatabaseTableStatisticsTableStatisticsCollection `pulumi:"tableStatisticsCollections"`
}

func GetManagedDatabaseTableStatisticsOutput(ctx *pulumi.Context, args GetManagedDatabaseTableStatisticsOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseTableStatisticsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseTableStatisticsResultOutput, error) {
			args := v.(GetManagedDatabaseTableStatisticsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getManagedDatabaseTableStatistics:getManagedDatabaseTableStatistics", args, GetManagedDatabaseTableStatisticsResultOutput{}, options).(GetManagedDatabaseTableStatisticsResultOutput), nil
		}).(GetManagedDatabaseTableStatisticsResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseTableStatistics.
type GetManagedDatabaseTableStatisticsOutputArgs struct {
	Filters GetManagedDatabaseTableStatisticsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
}

func (GetManagedDatabaseTableStatisticsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseTableStatisticsArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseTableStatistics.
type GetManagedDatabaseTableStatisticsResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseTableStatisticsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseTableStatisticsResult)(nil)).Elem()
}

func (o GetManagedDatabaseTableStatisticsResultOutput) ToGetManagedDatabaseTableStatisticsResultOutput() GetManagedDatabaseTableStatisticsResultOutput {
	return o
}

func (o GetManagedDatabaseTableStatisticsResultOutput) ToGetManagedDatabaseTableStatisticsResultOutputWithContext(ctx context.Context) GetManagedDatabaseTableStatisticsResultOutput {
	return o
}

func (o GetManagedDatabaseTableStatisticsResultOutput) Filters() GetManagedDatabaseTableStatisticsFilterArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseTableStatisticsResult) []GetManagedDatabaseTableStatisticsFilter {
		return v.Filters
	}).(GetManagedDatabaseTableStatisticsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseTableStatisticsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseTableStatisticsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagedDatabaseTableStatisticsResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseTableStatisticsResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// The list of table_statistics_collection.
func (o GetManagedDatabaseTableStatisticsResultOutput) TableStatisticsCollections() GetManagedDatabaseTableStatisticsTableStatisticsCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseTableStatisticsResult) []GetManagedDatabaseTableStatisticsTableStatisticsCollection {
		return v.TableStatisticsCollections
	}).(GetManagedDatabaseTableStatisticsTableStatisticsCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseTableStatisticsResultOutput{})
}
