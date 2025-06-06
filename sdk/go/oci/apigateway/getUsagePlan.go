// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Usage Plan resource in Oracle Cloud Infrastructure API Gateway service.
//
// Gets a usage plan by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/apigateway"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := apigateway.GetUsagePlan(ctx, &apigateway.GetUsagePlanArgs{
//				UsagePlanId: testUsagePlanOciApigatewayUsagePlan.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupUsagePlan(ctx *pulumi.Context, args *LookupUsagePlanArgs, opts ...pulumi.InvokeOption) (*LookupUsagePlanResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupUsagePlanResult
	err := ctx.Invoke("oci:ApiGateway/getUsagePlan:getUsagePlan", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getUsagePlan.
type LookupUsagePlanArgs struct {
	// The ocid of the usage plan.
	UsagePlanId string `pulumi:"usagePlanId"`
}

// A collection of values returned by getUsagePlan.
type LookupUsagePlanResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName string `pulumi:"displayName"`
	// A collection of entitlements currently assigned to the usage plan.
	Entitlements []GetUsagePlanEntitlement `pulumi:"entitlements"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a usage plan resource.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The current state of the usage plan.
	State string `pulumi:"state"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	UsagePlanId string `pulumi:"usagePlanId"`
}

func LookupUsagePlanOutput(ctx *pulumi.Context, args LookupUsagePlanOutputArgs, opts ...pulumi.InvokeOption) LookupUsagePlanResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupUsagePlanResultOutput, error) {
			args := v.(LookupUsagePlanArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApiGateway/getUsagePlan:getUsagePlan", args, LookupUsagePlanResultOutput{}, options).(LookupUsagePlanResultOutput), nil
		}).(LookupUsagePlanResultOutput)
}

// A collection of arguments for invoking getUsagePlan.
type LookupUsagePlanOutputArgs struct {
	// The ocid of the usage plan.
	UsagePlanId pulumi.StringInput `pulumi:"usagePlanId"`
}

func (LookupUsagePlanOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupUsagePlanArgs)(nil)).Elem()
}

// A collection of values returned by getUsagePlan.
type LookupUsagePlanResultOutput struct{ *pulumi.OutputState }

func (LookupUsagePlanResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupUsagePlanResult)(nil)).Elem()
}

func (o LookupUsagePlanResultOutput) ToLookupUsagePlanResultOutput() LookupUsagePlanResultOutput {
	return o
}

func (o LookupUsagePlanResultOutput) ToLookupUsagePlanResultOutputWithContext(ctx context.Context) LookupUsagePlanResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
func (o LookupUsagePlanResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupUsagePlanResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o LookupUsagePlanResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// A collection of entitlements currently assigned to the usage plan.
func (o LookupUsagePlanResultOutput) Entitlements() GetUsagePlanEntitlementArrayOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) []GetUsagePlanEntitlement { return v.Entitlements }).(GetUsagePlanEntitlementArrayOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupUsagePlanResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a usage plan resource.
func (o LookupUsagePlanResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o LookupUsagePlanResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current state of the usage plan.
func (o LookupUsagePlanResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.State }).(pulumi.StringOutput)
}

// The time this resource was created. An RFC3339 formatted datetime string.
func (o LookupUsagePlanResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time this resource was last updated. An RFC3339 formatted datetime string.
func (o LookupUsagePlanResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func (o LookupUsagePlanResultOutput) UsagePlanId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupUsagePlanResult) string { return v.UsagePlanId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupUsagePlanResultOutput{})
}
