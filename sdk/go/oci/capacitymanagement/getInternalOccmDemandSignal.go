// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Internal Occm Demand Signal resource in Oracle Cloud Infrastructure Capacity Management service.
//
// This is an internal GET API which gets the detailed information about a specific demand signal.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.GetInternalOccmDemandSignal(ctx, &capacitymanagement.GetInternalOccmDemandSignalArgs{
//				OccmDemandSignalId: testOccmDemandSignal.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupInternalOccmDemandSignal(ctx *pulumi.Context, args *LookupInternalOccmDemandSignalArgs, opts ...pulumi.InvokeOption) (*LookupInternalOccmDemandSignalResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupInternalOccmDemandSignalResult
	err := ctx.Invoke("oci:CapacityManagement/getInternalOccmDemandSignal:getInternalOccmDemandSignal", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getInternalOccmDemandSignal.
type LookupInternalOccmDemandSignalArgs struct {
	// The OCID of the demand signal.
	OccmDemandSignalId string `pulumi:"occmDemandSignalId"`
}

// A collection of values returned by getInternalOccmDemandSignal.
type LookupInternalOccmDemandSignalResult struct {
	// The OCID of the tenancy from which the request to create the demand signal was made.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A short description about the demand signal.
	Description string `pulumi:"description"`
	// The display name of the demand signal.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the demand signal.
	Id string `pulumi:"id"`
	// The different states associated with a demand signal.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The OCID of the customer group in which the demand signal is created.
	OccCustomerGroupId string `pulumi:"occCustomerGroupId"`
	OccmDemandSignalId string `pulumi:"occmDemandSignalId"`
	// The current lifecycle state of the demand signal.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the demand signal was created.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the demand signal was last updated.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupInternalOccmDemandSignalOutput(ctx *pulumi.Context, args LookupInternalOccmDemandSignalOutputArgs, opts ...pulumi.InvokeOption) LookupInternalOccmDemandSignalResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupInternalOccmDemandSignalResultOutput, error) {
			args := v.(LookupInternalOccmDemandSignalArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CapacityManagement/getInternalOccmDemandSignal:getInternalOccmDemandSignal", args, LookupInternalOccmDemandSignalResultOutput{}, options).(LookupInternalOccmDemandSignalResultOutput), nil
		}).(LookupInternalOccmDemandSignalResultOutput)
}

// A collection of arguments for invoking getInternalOccmDemandSignal.
type LookupInternalOccmDemandSignalOutputArgs struct {
	// The OCID of the demand signal.
	OccmDemandSignalId pulumi.StringInput `pulumi:"occmDemandSignalId"`
}

func (LookupInternalOccmDemandSignalOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupInternalOccmDemandSignalArgs)(nil)).Elem()
}

// A collection of values returned by getInternalOccmDemandSignal.
type LookupInternalOccmDemandSignalResultOutput struct{ *pulumi.OutputState }

func (LookupInternalOccmDemandSignalResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupInternalOccmDemandSignalResult)(nil)).Elem()
}

func (o LookupInternalOccmDemandSignalResultOutput) ToLookupInternalOccmDemandSignalResultOutput() LookupInternalOccmDemandSignalResultOutput {
	return o
}

func (o LookupInternalOccmDemandSignalResultOutput) ToLookupInternalOccmDemandSignalResultOutputWithContext(ctx context.Context) LookupInternalOccmDemandSignalResultOutput {
	return o
}

// The OCID of the tenancy from which the request to create the demand signal was made.
func (o LookupInternalOccmDemandSignalResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupInternalOccmDemandSignalResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A short description about the demand signal.
func (o LookupInternalOccmDemandSignalResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the demand signal.
func (o LookupInternalOccmDemandSignalResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupInternalOccmDemandSignalResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the demand signal.
func (o LookupInternalOccmDemandSignalResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.Id }).(pulumi.StringOutput)
}

// The different states associated with a demand signal.
func (o LookupInternalOccmDemandSignalResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the customer group in which the demand signal is created.
func (o LookupInternalOccmDemandSignalResultOutput) OccCustomerGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.OccCustomerGroupId }).(pulumi.StringOutput)
}

func (o LookupInternalOccmDemandSignalResultOutput) OccmDemandSignalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.OccmDemandSignalId }).(pulumi.StringOutput)
}

// The current lifecycle state of the demand signal.
func (o LookupInternalOccmDemandSignalResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupInternalOccmDemandSignalResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the demand signal was created.
func (o LookupInternalOccmDemandSignalResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the demand signal was last updated.
func (o LookupInternalOccmDemandSignalResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupInternalOccmDemandSignalResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupInternalOccmDemandSignalResultOutput{})
}
