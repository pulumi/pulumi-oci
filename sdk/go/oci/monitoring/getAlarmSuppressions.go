// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package monitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Alarm Suppressions in Oracle Cloud Infrastructure Monitoring service.
//
// Lists alarm suppressions for the specified alarm.
// Only dimension-level suppressions are listed. Alarm-level suppressions are not listed.
//
// For important limits information, see
// [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).
//
// This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
// Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
// or transactions, per second (TPS) for a given tenancy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/Monitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Monitoring.GetAlarmSuppressions(ctx, &monitoring.GetAlarmSuppressionsArgs{
//				AlarmId:     testAlarm.Id,
//				DisplayName: pulumi.StringRef(alarmSuppressionDisplayName),
//				State:       pulumi.StringRef(alarmSuppressionState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAlarmSuppressions(ctx *pulumi.Context, args *GetAlarmSuppressionsArgs, opts ...pulumi.InvokeOption) (*GetAlarmSuppressionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAlarmSuppressionsResult
	err := ctx.Invoke("oci:Monitoring/getAlarmSuppressions:getAlarmSuppressions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAlarmSuppressions.
type GetAlarmSuppressionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
	AlarmId string `pulumi:"alarmId"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list a alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetAlarmSuppressionsFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAlarmSuppressions.
type GetAlarmSuppressionsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
	AlarmId string `pulumi:"alarmId"`
	// The list of alarm_suppression_collection.
	AlarmSuppressionCollections []GetAlarmSuppressionsAlarmSuppressionCollection `pulumi:"alarmSuppressionCollections"`
	// A user-friendly name for the alarm suppression. It does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetAlarmSuppressionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the alarm suppression.  Example: `DELETED`
	State *string `pulumi:"state"`
}

func GetAlarmSuppressionsOutput(ctx *pulumi.Context, args GetAlarmSuppressionsOutputArgs, opts ...pulumi.InvokeOption) GetAlarmSuppressionsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAlarmSuppressionsResultOutput, error) {
			args := v.(GetAlarmSuppressionsArgs)
			opts = internal.PkgInvokeDefaultOpts(opts)
			var rv GetAlarmSuppressionsResult
			secret, err := ctx.InvokePackageRaw("oci:Monitoring/getAlarmSuppressions:getAlarmSuppressions", args, &rv, "", opts...)
			if err != nil {
				return GetAlarmSuppressionsResultOutput{}, err
			}

			output := pulumi.ToOutput(rv).(GetAlarmSuppressionsResultOutput)
			if secret {
				return pulumi.ToSecret(output).(GetAlarmSuppressionsResultOutput), nil
			}
			return output, nil
		}).(GetAlarmSuppressionsResultOutput)
}

// A collection of arguments for invoking getAlarmSuppressions.
type GetAlarmSuppressionsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
	AlarmId pulumi.StringInput `pulumi:"alarmId"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list a alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
	DisplayName pulumi.StringPtrInput                `pulumi:"displayName"`
	Filters     GetAlarmSuppressionsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAlarmSuppressionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAlarmSuppressionsArgs)(nil)).Elem()
}

// A collection of values returned by getAlarmSuppressions.
type GetAlarmSuppressionsResultOutput struct{ *pulumi.OutputState }

func (GetAlarmSuppressionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAlarmSuppressionsResult)(nil)).Elem()
}

func (o GetAlarmSuppressionsResultOutput) ToGetAlarmSuppressionsResultOutput() GetAlarmSuppressionsResultOutput {
	return o
}

func (o GetAlarmSuppressionsResultOutput) ToGetAlarmSuppressionsResultOutputWithContext(ctx context.Context) GetAlarmSuppressionsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
func (o GetAlarmSuppressionsResultOutput) AlarmId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) string { return v.AlarmId }).(pulumi.StringOutput)
}

// The list of alarm_suppression_collection.
func (o GetAlarmSuppressionsResultOutput) AlarmSuppressionCollections() GetAlarmSuppressionsAlarmSuppressionCollectionArrayOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) []GetAlarmSuppressionsAlarmSuppressionCollection {
		return v.AlarmSuppressionCollections
	}).(GetAlarmSuppressionsAlarmSuppressionCollectionArrayOutput)
}

// A user-friendly name for the alarm suppression. It does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetAlarmSuppressionsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAlarmSuppressionsResultOutput) Filters() GetAlarmSuppressionsFilterArrayOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) []GetAlarmSuppressionsFilter { return v.Filters }).(GetAlarmSuppressionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAlarmSuppressionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current lifecycle state of the alarm suppression.  Example: `DELETED`
func (o GetAlarmSuppressionsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAlarmSuppressionsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAlarmSuppressionsResultOutput{})
}
