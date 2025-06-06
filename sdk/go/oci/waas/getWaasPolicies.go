// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waas

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Waas Policies in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
//
// Gets a list of WAAS policies.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/waas"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := waas.GetWaasPolicies(ctx, &waas.GetWaasPoliciesArgs{
//				CompartmentId:                   compartmentId,
//				DisplayNames:                    waasPolicyDisplayNames,
//				Ids:                             waasPolicyIds,
//				States:                          waasPolicyStates,
//				TimeCreatedGreaterThanOrEqualTo: pulumi.StringRef(waasPolicyTimeCreatedGreaterThanOrEqualTo),
//				TimeCreatedLessThan:             pulumi.StringRef(waasPolicyTimeCreatedLessThan),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetWaasPolicies(ctx *pulumi.Context, args *GetWaasPoliciesArgs, opts ...pulumi.InvokeOption) (*GetWaasPoliciesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetWaasPoliciesResult
	err := ctx.Invoke("oci:Waas/getWaasPolicies:getWaasPolicies", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWaasPolicies.
type GetWaasPoliciesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
	CompartmentId string `pulumi:"compartmentId"`
	// Filter policies using a list of display names.
	DisplayNames []string                `pulumi:"displayNames"`
	Filters      []GetWaasPoliciesFilter `pulumi:"filters"`
	// Filter policies using a list of policy OCIDs.
	Ids []string `pulumi:"ids"`
	// Filter policies using a list of lifecycle states.
	States []string `pulumi:"states"`
	// A filter that matches policies created on or after the specified date and time.
	TimeCreatedGreaterThanOrEqualTo *string `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	// A filter that matches policies created before the specified date-time.
	TimeCreatedLessThan *string `pulumi:"timeCreatedLessThan"`
}

// A collection of values returned by getWaasPolicies.
type GetWaasPoliciesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy's compartment.
	CompartmentId string                  `pulumi:"compartmentId"`
	DisplayNames  []string                `pulumi:"displayNames"`
	Filters       []GetWaasPoliciesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                              string   `pulumi:"id"`
	Ids                             []string `pulumi:"ids"`
	States                          []string `pulumi:"states"`
	TimeCreatedGreaterThanOrEqualTo *string  `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	TimeCreatedLessThan             *string  `pulumi:"timeCreatedLessThan"`
	// The list of waas_policies.
	WaasPolicies []GetWaasPoliciesWaasPolicy `pulumi:"waasPolicies"`
}

func GetWaasPoliciesOutput(ctx *pulumi.Context, args GetWaasPoliciesOutputArgs, opts ...pulumi.InvokeOption) GetWaasPoliciesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetWaasPoliciesResultOutput, error) {
			args := v.(GetWaasPoliciesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Waas/getWaasPolicies:getWaasPolicies", args, GetWaasPoliciesResultOutput{}, options).(GetWaasPoliciesResultOutput), nil
		}).(GetWaasPoliciesResultOutput)
}

// A collection of arguments for invoking getWaasPolicies.
type GetWaasPoliciesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This number is generated when the compartment is created.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Filter policies using a list of display names.
	DisplayNames pulumi.StringArrayInput         `pulumi:"displayNames"`
	Filters      GetWaasPoliciesFilterArrayInput `pulumi:"filters"`
	// Filter policies using a list of policy OCIDs.
	Ids pulumi.StringArrayInput `pulumi:"ids"`
	// Filter policies using a list of lifecycle states.
	States pulumi.StringArrayInput `pulumi:"states"`
	// A filter that matches policies created on or after the specified date and time.
	TimeCreatedGreaterThanOrEqualTo pulumi.StringPtrInput `pulumi:"timeCreatedGreaterThanOrEqualTo"`
	// A filter that matches policies created before the specified date-time.
	TimeCreatedLessThan pulumi.StringPtrInput `pulumi:"timeCreatedLessThan"`
}

func (GetWaasPoliciesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWaasPoliciesArgs)(nil)).Elem()
}

// A collection of values returned by getWaasPolicies.
type GetWaasPoliciesResultOutput struct{ *pulumi.OutputState }

func (GetWaasPoliciesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWaasPoliciesResult)(nil)).Elem()
}

func (o GetWaasPoliciesResultOutput) ToGetWaasPoliciesResultOutput() GetWaasPoliciesResultOutput {
	return o
}

func (o GetWaasPoliciesResultOutput) ToGetWaasPoliciesResultOutputWithContext(ctx context.Context) GetWaasPoliciesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy's compartment.
func (o GetWaasPoliciesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetWaasPoliciesResultOutput) DisplayNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) []string { return v.DisplayNames }).(pulumi.StringArrayOutput)
}

func (o GetWaasPoliciesResultOutput) Filters() GetWaasPoliciesFilterArrayOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) []GetWaasPoliciesFilter { return v.Filters }).(GetWaasPoliciesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetWaasPoliciesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetWaasPoliciesResultOutput) Ids() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) []string { return v.Ids }).(pulumi.StringArrayOutput)
}

func (o GetWaasPoliciesResultOutput) States() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) []string { return v.States }).(pulumi.StringArrayOutput)
}

func (o GetWaasPoliciesResultOutput) TimeCreatedGreaterThanOrEqualTo() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) *string { return v.TimeCreatedGreaterThanOrEqualTo }).(pulumi.StringPtrOutput)
}

func (o GetWaasPoliciesResultOutput) TimeCreatedLessThan() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) *string { return v.TimeCreatedLessThan }).(pulumi.StringPtrOutput)
}

// The list of waas_policies.
func (o GetWaasPoliciesResultOutput) WaasPolicies() GetWaasPoliciesWaasPolicyArrayOutput {
	return o.ApplyT(func(v GetWaasPoliciesResult) []GetWaasPoliciesWaasPolicy { return v.WaasPolicies }).(GetWaasPoliciesWaasPolicyArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetWaasPoliciesResultOutput{})
}
