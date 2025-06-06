// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waas

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Protection Rules in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
//
// Gets the list of available protection rules for a WAAS policy. Use the `GetWafConfig` operation to view a list of currently configured protection rules for the Web Application Firewall, or use the `ListRecommendations` operation to get a list of recommended protection rules for the Web Application Firewall.
// The list is sorted by `key`, in ascending order.
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
//			_, err := waas.GetProtectionRules(ctx, &waas.GetProtectionRulesArgs{
//				WaasPolicyId:       testWaasPolicy.Id,
//				Actions:            protectionRuleAction,
//				ModSecurityRuleIds: testRule.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProtectionRules(ctx *pulumi.Context, args *GetProtectionRulesArgs, opts ...pulumi.InvokeOption) (*GetProtectionRulesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetProtectionRulesResult
	err := ctx.Invoke("oci:Waas/getProtectionRules:getProtectionRules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProtectionRules.
type GetProtectionRulesArgs struct {
	// Filter rules using a list of actions.
	Actions []string                   `pulumi:"actions"`
	Filters []GetProtectionRulesFilter `pulumi:"filters"`
	// Filter rules using a list of ModSecurity rule IDs.
	ModSecurityRuleIds []string `pulumi:"modSecurityRuleIds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId string `pulumi:"waasPolicyId"`
}

// A collection of values returned by getProtectionRules.
type GetProtectionRulesResult struct {
	// The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Actions []string                   `pulumi:"actions"`
	Filters []GetProtectionRulesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                 string   `pulumi:"id"`
	ModSecurityRuleIds []string `pulumi:"modSecurityRuleIds"`
	// The list of protection_rules.
	ProtectionRules []GetProtectionRulesProtectionRule `pulumi:"protectionRules"`
	WaasPolicyId    string                             `pulumi:"waasPolicyId"`
}

func GetProtectionRulesOutput(ctx *pulumi.Context, args GetProtectionRulesOutputArgs, opts ...pulumi.InvokeOption) GetProtectionRulesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetProtectionRulesResultOutput, error) {
			args := v.(GetProtectionRulesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Waas/getProtectionRules:getProtectionRules", args, GetProtectionRulesResultOutput{}, options).(GetProtectionRulesResultOutput), nil
		}).(GetProtectionRulesResultOutput)
}

// A collection of arguments for invoking getProtectionRules.
type GetProtectionRulesOutputArgs struct {
	// Filter rules using a list of actions.
	Actions pulumi.StringArrayInput            `pulumi:"actions"`
	Filters GetProtectionRulesFilterArrayInput `pulumi:"filters"`
	// Filter rules using a list of ModSecurity rule IDs.
	ModSecurityRuleIds pulumi.StringArrayInput `pulumi:"modSecurityRuleIds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId pulumi.StringInput `pulumi:"waasPolicyId"`
}

func (GetProtectionRulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProtectionRulesArgs)(nil)).Elem()
}

// A collection of values returned by getProtectionRules.
type GetProtectionRulesResultOutput struct{ *pulumi.OutputState }

func (GetProtectionRulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProtectionRulesResult)(nil)).Elem()
}

func (o GetProtectionRulesResultOutput) ToGetProtectionRulesResultOutput() GetProtectionRulesResultOutput {
	return o
}

func (o GetProtectionRulesResultOutput) ToGetProtectionRulesResultOutputWithContext(ctx context.Context) GetProtectionRulesResultOutput {
	return o
}

// The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
func (o GetProtectionRulesResultOutput) Actions() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) []string { return v.Actions }).(pulumi.StringArrayOutput)
}

func (o GetProtectionRulesResultOutput) Filters() GetProtectionRulesFilterArrayOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) []GetProtectionRulesFilter { return v.Filters }).(GetProtectionRulesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetProtectionRulesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetProtectionRulesResultOutput) ModSecurityRuleIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) []string { return v.ModSecurityRuleIds }).(pulumi.StringArrayOutput)
}

// The list of protection_rules.
func (o GetProtectionRulesResultOutput) ProtectionRules() GetProtectionRulesProtectionRuleArrayOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) []GetProtectionRulesProtectionRule { return v.ProtectionRules }).(GetProtectionRulesProtectionRuleArrayOutput)
}

func (o GetProtectionRulesResultOutput) WaasPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetProtectionRulesResult) string { return v.WaasPolicyId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetProtectionRulesResultOutput{})
}
