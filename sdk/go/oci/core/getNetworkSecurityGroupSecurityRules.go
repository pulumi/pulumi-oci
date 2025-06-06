// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Network Security Group Security Rules in Oracle Cloud Infrastructure Core service.
//
// Lists the security rules in the specified network security group.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetNetworkSecurityGroupSecurityRules(ctx, &core.GetNetworkSecurityGroupSecurityRulesArgs{
//				NetworkSecurityGroupId: testNetworkSecurityGroup.Id,
//				Direction:              pulumi.StringRef(networkSecurityGroupSecurityRuleDirection),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetNetworkSecurityGroupSecurityRules(ctx *pulumi.Context, args *GetNetworkSecurityGroupSecurityRulesArgs, opts ...pulumi.InvokeOption) (*GetNetworkSecurityGroupSecurityRulesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetNetworkSecurityGroupSecurityRulesResult
	err := ctx.Invoke("oci:Core/getNetworkSecurityGroupSecurityRules:getNetworkSecurityGroupSecurityRules", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNetworkSecurityGroupSecurityRules.
type GetNetworkSecurityGroupSecurityRulesArgs struct {
	// Direction of the security rule. Set to `EGRESS` for rules that allow outbound IP packets, or `INGRESS` for rules that allow inbound IP packets.
	Direction *string                                      `pulumi:"direction"`
	Filters   []GetNetworkSecurityGroupSecurityRulesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId string `pulumi:"networkSecurityGroupId"`
}

// A collection of values returned by getNetworkSecurityGroupSecurityRules.
type GetNetworkSecurityGroupSecurityRulesResult struct {
	// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
	Direction *string                                      `pulumi:"direction"`
	Filters   []GetNetworkSecurityGroupSecurityRulesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                     string `pulumi:"id"`
	NetworkSecurityGroupId string `pulumi:"networkSecurityGroupId"`
	// The list of security_rules.
	SecurityRules []GetNetworkSecurityGroupSecurityRulesSecurityRule `pulumi:"securityRules"`
}

func GetNetworkSecurityGroupSecurityRulesOutput(ctx *pulumi.Context, args GetNetworkSecurityGroupSecurityRulesOutputArgs, opts ...pulumi.InvokeOption) GetNetworkSecurityGroupSecurityRulesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetNetworkSecurityGroupSecurityRulesResultOutput, error) {
			args := v.(GetNetworkSecurityGroupSecurityRulesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getNetworkSecurityGroupSecurityRules:getNetworkSecurityGroupSecurityRules", args, GetNetworkSecurityGroupSecurityRulesResultOutput{}, options).(GetNetworkSecurityGroupSecurityRulesResultOutput), nil
		}).(GetNetworkSecurityGroupSecurityRulesResultOutput)
}

// A collection of arguments for invoking getNetworkSecurityGroupSecurityRules.
type GetNetworkSecurityGroupSecurityRulesOutputArgs struct {
	// Direction of the security rule. Set to `EGRESS` for rules that allow outbound IP packets, or `INGRESS` for rules that allow inbound IP packets.
	Direction pulumi.StringPtrInput                                `pulumi:"direction"`
	Filters   GetNetworkSecurityGroupSecurityRulesFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security group.
	NetworkSecurityGroupId pulumi.StringInput `pulumi:"networkSecurityGroupId"`
}

func (GetNetworkSecurityGroupSecurityRulesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkSecurityGroupSecurityRulesArgs)(nil)).Elem()
}

// A collection of values returned by getNetworkSecurityGroupSecurityRules.
type GetNetworkSecurityGroupSecurityRulesResultOutput struct{ *pulumi.OutputState }

func (GetNetworkSecurityGroupSecurityRulesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetNetworkSecurityGroupSecurityRulesResult)(nil)).Elem()
}

func (o GetNetworkSecurityGroupSecurityRulesResultOutput) ToGetNetworkSecurityGroupSecurityRulesResultOutput() GetNetworkSecurityGroupSecurityRulesResultOutput {
	return o
}

func (o GetNetworkSecurityGroupSecurityRulesResultOutput) ToGetNetworkSecurityGroupSecurityRulesResultOutputWithContext(ctx context.Context) GetNetworkSecurityGroupSecurityRulesResultOutput {
	return o
}

// Direction of the security rule. Set to `EGRESS` for rules to allow outbound IP packets, or `INGRESS` for rules to allow inbound IP packets.
func (o GetNetworkSecurityGroupSecurityRulesResultOutput) Direction() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetNetworkSecurityGroupSecurityRulesResult) *string { return v.Direction }).(pulumi.StringPtrOutput)
}

func (o GetNetworkSecurityGroupSecurityRulesResultOutput) Filters() GetNetworkSecurityGroupSecurityRulesFilterArrayOutput {
	return o.ApplyT(func(v GetNetworkSecurityGroupSecurityRulesResult) []GetNetworkSecurityGroupSecurityRulesFilter {
		return v.Filters
	}).(GetNetworkSecurityGroupSecurityRulesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetNetworkSecurityGroupSecurityRulesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkSecurityGroupSecurityRulesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetNetworkSecurityGroupSecurityRulesResultOutput) NetworkSecurityGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v GetNetworkSecurityGroupSecurityRulesResult) string { return v.NetworkSecurityGroupId }).(pulumi.StringOutput)
}

// The list of security_rules.
func (o GetNetworkSecurityGroupSecurityRulesResultOutput) SecurityRules() GetNetworkSecurityGroupSecurityRulesSecurityRuleArrayOutput {
	return o.ApplyT(func(v GetNetworkSecurityGroupSecurityRulesResult) []GetNetworkSecurityGroupSecurityRulesSecurityRule {
		return v.SecurityRules
	}).(GetNetworkSecurityGroupSecurityRulesSecurityRuleArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetNetworkSecurityGroupSecurityRulesResultOutput{})
}
