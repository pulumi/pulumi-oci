// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Database Alert Log Count resource in Oracle Cloud Infrastructure Database Management service.
//
// Get the counts of alert logs for the specified Managed Database.
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
//			_, err := DatabaseManagement.GetManagedDatabaseAlertLogCount(ctx, &databasemanagement.GetManagedDatabaseAlertLogCountArgs{
//				ManagedDatabaseId:        oci_database_management_managed_database.Test_managed_database.Id,
//				GroupBy:                  pulumi.StringRef(_var.Managed_database_alert_log_count_group_by),
//				IsRegularExpression:      pulumi.BoolRef(_var.Managed_database_alert_log_count_is_regular_expression),
//				LevelFilter:              pulumi.StringRef(_var.Managed_database_alert_log_count_level_filter),
//				LogSearchText:            pulumi.StringRef(_var.Managed_database_alert_log_count_log_search_text),
//				TimeGreaterThanOrEqualTo: pulumi.StringRef(_var.Managed_database_alert_log_count_time_greater_than_or_equal_to),
//				TimeLessThanOrEqualTo:    pulumi.StringRef(_var.Managed_database_alert_log_count_time_less_than_or_equal_to),
//				TypeFilter:               pulumi.StringRef(_var.Managed_database_alert_log_count_type_filter),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseAlertLogCount(ctx *pulumi.Context, args *GetManagedDatabaseAlertLogCountArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseAlertLogCountResult, error) {
	var rv GetManagedDatabaseAlertLogCountResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseAlertLogCount:getManagedDatabaseAlertLogCount", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseAlertLogCount.
type GetManagedDatabaseAlertLogCountArgs struct {
	// The optional parameter used to group different alert logs.
	GroupBy *string `pulumi:"groupBy"`
	// The flag to indicate whether the search text is regular expression or not.
	IsRegularExpression *bool `pulumi:"isRegularExpression"`
	// The optional parameter to filter the alert logs by log level.
	LevelFilter *string `pulumi:"levelFilter"`
	// The optional query parameter to filter the attention or alert logs by search text.
	LogSearchText *string `pulumi:"logSearchText"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The optional greater than or equal to timestamp to filter the logs.
	TimeGreaterThanOrEqualTo *string `pulumi:"timeGreaterThanOrEqualTo"`
	// The optional less than or equal to timestamp to filter the logs.
	TimeLessThanOrEqualTo *string `pulumi:"timeLessThanOrEqualTo"`
	// The optional parameter to filter the attention or alert logs by type.
	TypeFilter *string `pulumi:"typeFilter"`
}

// A collection of values returned by getManagedDatabaseAlertLogCount.
type GetManagedDatabaseAlertLogCountResult struct {
	GroupBy *string `pulumi:"groupBy"`
	// The provider-assigned unique ID for this managed resource.
	Id                  string `pulumi:"id"`
	IsRegularExpression *bool  `pulumi:"isRegularExpression"`
	// An array of the counts of different urgency or type of alert logs.
	Items         []GetManagedDatabaseAlertLogCountItem `pulumi:"items"`
	LevelFilter   *string                               `pulumi:"levelFilter"`
	LogSearchText *string                               `pulumi:"logSearchText"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId        string  `pulumi:"managedDatabaseId"`
	TimeGreaterThanOrEqualTo *string `pulumi:"timeGreaterThanOrEqualTo"`
	TimeLessThanOrEqualTo    *string `pulumi:"timeLessThanOrEqualTo"`
	TypeFilter               *string `pulumi:"typeFilter"`
}

func GetManagedDatabaseAlertLogCountOutput(ctx *pulumi.Context, args GetManagedDatabaseAlertLogCountOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseAlertLogCountResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseAlertLogCountResult, error) {
			args := v.(GetManagedDatabaseAlertLogCountArgs)
			r, err := GetManagedDatabaseAlertLogCount(ctx, &args, opts...)
			var s GetManagedDatabaseAlertLogCountResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedDatabaseAlertLogCountResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseAlertLogCount.
type GetManagedDatabaseAlertLogCountOutputArgs struct {
	// The optional parameter used to group different alert logs.
	GroupBy pulumi.StringPtrInput `pulumi:"groupBy"`
	// The flag to indicate whether the search text is regular expression or not.
	IsRegularExpression pulumi.BoolPtrInput `pulumi:"isRegularExpression"`
	// The optional parameter to filter the alert logs by log level.
	LevelFilter pulumi.StringPtrInput `pulumi:"levelFilter"`
	// The optional query parameter to filter the attention or alert logs by search text.
	LogSearchText pulumi.StringPtrInput `pulumi:"logSearchText"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
	// The optional greater than or equal to timestamp to filter the logs.
	TimeGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeGreaterThanOrEqualTo"`
	// The optional less than or equal to timestamp to filter the logs.
	TimeLessThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeLessThanOrEqualTo"`
	// The optional parameter to filter the attention or alert logs by type.
	TypeFilter pulumi.StringPtrInput `pulumi:"typeFilter"`
}

func (GetManagedDatabaseAlertLogCountOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseAlertLogCountArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseAlertLogCount.
type GetManagedDatabaseAlertLogCountResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseAlertLogCountResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseAlertLogCountResult)(nil)).Elem()
}

func (o GetManagedDatabaseAlertLogCountResultOutput) ToGetManagedDatabaseAlertLogCountResultOutput() GetManagedDatabaseAlertLogCountResultOutput {
	return o
}

func (o GetManagedDatabaseAlertLogCountResultOutput) ToGetManagedDatabaseAlertLogCountResultOutputWithContext(ctx context.Context) GetManagedDatabaseAlertLogCountResultOutput {
	return o
}

func (o GetManagedDatabaseAlertLogCountResultOutput) GroupBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.GroupBy }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseAlertLogCountResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) IsRegularExpression() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *bool { return v.IsRegularExpression }).(pulumi.BoolPtrOutput)
}

// An array of the counts of different urgency or type of alert logs.
func (o GetManagedDatabaseAlertLogCountResultOutput) Items() GetManagedDatabaseAlertLogCountItemArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) []GetManagedDatabaseAlertLogCountItem { return v.Items }).(GetManagedDatabaseAlertLogCountItemArrayOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) LevelFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.LevelFilter }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) LogSearchText() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.LogSearchText }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
func (o GetManagedDatabaseAlertLogCountResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) TimeGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.TimeGreaterThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) TimeLessThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.TimeLessThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseAlertLogCountResultOutput) TypeFilter() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseAlertLogCountResult) *string { return v.TypeFilter }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseAlertLogCountResultOutput{})
}