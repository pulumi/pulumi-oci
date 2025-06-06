// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package monitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Alarms in Oracle Cloud Infrastructure Monitoring service.
//
// Lists the alarms for the specified compartment.
// For more information, see
// [Listing Alarms](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Tasks/list-alarm.htm).
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
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/monitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := monitoring.GetAlarms(ctx, &monitoring.GetAlarmsArgs{
//				CompartmentId:          compartmentId,
//				CompartmentIdInSubtree: pulumi.BoolRef(alarmCompartmentIdInSubtree),
//				DisplayName:            pulumi.StringRef(alarmDisplayName),
//				State:                  pulumi.StringRef(alarmState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAlarms(ctx *pulumi.Context, args *GetAlarmsArgs, opts ...pulumi.InvokeOption) (*GetAlarmsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAlarmsResult
	err := ctx.Invoke("oci:Monitoring/getAlarms:getAlarms", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAlarms.
type GetAlarmsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
	CompartmentId string `pulumi:"compartmentId"`
	// When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetAlarmsFilter `pulumi:"filters"`
	// A filter to return only alarms that match the given lifecycle state exactly. When not specified, only alarms in the ACTIVE lifecycle state are listed.
	State *string `pulumi:"state"`
}

// A collection of values returned by getAlarms.
type GetAlarmsResult struct {
	// The list of alarms.
	Alarms []GetAlarmsAlarm `pulumi:"alarms"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// A user-friendly name for the alarm. It does not have to be unique, and it's changeable.
	DisplayName *string           `pulumi:"displayName"`
	Filters     []GetAlarmsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current lifecycle state of the alarm.  Example: `DELETED`
	State *string `pulumi:"state"`
}

func GetAlarmsOutput(ctx *pulumi.Context, args GetAlarmsOutputArgs, opts ...pulumi.InvokeOption) GetAlarmsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAlarmsResultOutput, error) {
			args := v.(GetAlarmsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Monitoring/getAlarms:getAlarms", args, GetAlarmsResultOutput{}, options).(GetAlarmsResultOutput), nil
		}).(GetAlarmsResultOutput)
}

// A collection of arguments for invoking getAlarms.
type GetAlarmsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the resources monitored by the metric that you are searching for. Use tenancyId to search in the root compartment.  Example: `ocid1.compartment.oc1..exampleuniqueID`
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// When true, returns resources from all compartments and subcompartments. The parameter can only be set to true when compartmentId is the tenancy OCID (the tenancy is the root compartment). A true value requires the user to have tenancy-level permissions. If this requirement is not met, then the call is rejected. When false, returns resources from only the compartment specified in compartmentId. Default is false.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// A filter to return only resources that match the given display name exactly. Use this filter to list an alarm by name. Alternatively, when you know the alarm OCID, use the GetAlarm operation.
	DisplayName pulumi.StringPtrInput     `pulumi:"displayName"`
	Filters     GetAlarmsFilterArrayInput `pulumi:"filters"`
	// A filter to return only alarms that match the given lifecycle state exactly. When not specified, only alarms in the ACTIVE lifecycle state are listed.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetAlarmsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAlarmsArgs)(nil)).Elem()
}

// A collection of values returned by getAlarms.
type GetAlarmsResultOutput struct{ *pulumi.OutputState }

func (GetAlarmsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAlarmsResult)(nil)).Elem()
}

func (o GetAlarmsResultOutput) ToGetAlarmsResultOutput() GetAlarmsResultOutput {
	return o
}

func (o GetAlarmsResultOutput) ToGetAlarmsResultOutputWithContext(ctx context.Context) GetAlarmsResultOutput {
	return o
}

// The list of alarms.
func (o GetAlarmsResultOutput) Alarms() GetAlarmsAlarmArrayOutput {
	return o.ApplyT(func(v GetAlarmsResult) []GetAlarmsAlarm { return v.Alarms }).(GetAlarmsAlarmArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the alarm.
func (o GetAlarmsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAlarmsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetAlarmsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetAlarmsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// A user-friendly name for the alarm. It does not have to be unique, and it's changeable.
func (o GetAlarmsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAlarmsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetAlarmsResultOutput) Filters() GetAlarmsFilterArrayOutput {
	return o.ApplyT(func(v GetAlarmsResult) []GetAlarmsFilter { return v.Filters }).(GetAlarmsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAlarmsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAlarmsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current lifecycle state of the alarm.  Example: `DELETED`
func (o GetAlarmsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAlarmsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAlarmsResultOutput{})
}
