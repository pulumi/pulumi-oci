// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package events

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Rules in Oracle Cloud Infrastructure Events service.
//
// Lists rules for this compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/events"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := events.GetRules(ctx, &events.GetRulesArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(ruleDisplayName),
//				State:         pulumi.StringRef(ruleState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRules(ctx *pulumi.Context, args *GetRulesArgs, opts ...pulumi.InvokeOption) (*GetRulesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRulesResult
	err := ctx.Invoke("oci:Events/getRules:getRules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRules.
type GetRulesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only rules with descriptions that match the displayName string in this parameter.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetRulesFilter `pulumi:"filters"`
	// A filter to return only rules that match the lifecycle state in this parameter.  Example: `Creating`
	State *string `pulumi:"state"`
}

// A collection of values returned by getRules.
type GetRulesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId string `pulumi:"compartmentId"`
	// A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetRulesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of rules.
	Rules []GetRulesRule `pulumi:"rules"`
	// The current state of the rule.
	State *string `pulumi:"state"`
}

func GetRulesOutput(ctx *pulumi.Context, args GetRulesOutputArgs, opts ...pulumi.InvokeOption) GetRulesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetRulesResultOutput, error) {
			args := v.(GetRulesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Events/getRules:getRules", args, GetRulesResultOutput{}, options).(GetRulesResultOutput), nil
		}).(GetRulesResultOutput)
}

// A collection of arguments for invoking getRules.
type GetRulesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only rules with descriptions that match the displayName string in this parameter.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
	DisplayName pulumi.StringPtrInput    `pulumi:"displayName"`
	Filters     GetRulesFilterArrayInput `pulumi:"filters"`
	// A filter to return only rules that match the lifecycle state in this parameter.  Example: `Creating`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetRulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRulesArgs)(nil)).Elem()
}

// A collection of values returned by getRules.
type GetRulesResultOutput struct{ *pulumi.OutputState }

func (GetRulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRulesResult)(nil)).Elem()
}

func (o GetRulesResultOutput) ToGetRulesResultOutput() GetRulesResultOutput {
	return o
}

func (o GetRulesResultOutput) ToGetRulesResultOutputWithContext(ctx context.Context) GetRulesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to which this rule belongs.
func (o GetRulesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRulesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A string that describes the rule. It does not have to be unique, and you can change it. Avoid entering confidential information.  Example: `"This rule sends a notification upon completion of DbaaS backup."`
func (o GetRulesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRulesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetRulesResultOutput) Filters() GetRulesFilterArrayOutput {
	return o.ApplyT(func(v GetRulesResult) []GetRulesFilter { return v.Filters }).(GetRulesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRulesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRulesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of rules.
func (o GetRulesResultOutput) Rules() GetRulesRuleArrayOutput {
	return o.ApplyT(func(v GetRulesResult) []GetRulesRule { return v.Rules }).(GetRulesRuleArrayOutput)
}

// The current state of the rule.
func (o GetRulesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRulesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRulesResultOutput{})
}
