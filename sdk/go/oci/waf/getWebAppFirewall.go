// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waf

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Web App Firewall resource in Oracle Cloud Infrastructure Waf service.
//
// Gets a WebAppFirewall by OCID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Waf"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Waf.GetWebAppFirewall(ctx, &waf.GetWebAppFirewallArgs{
//				WebAppFirewallId: oci_waf_web_app_firewall.Test_web_app_firewall.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetWebAppFirewall(ctx *pulumi.Context, args *GetWebAppFirewallArgs, opts ...pulumi.InvokeOption) (*GetWebAppFirewallResult, error) {
	var rv GetWebAppFirewallResult
	err := ctx.Invoke("oci:Waf/getWebAppFirewall:getWebAppFirewall", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWebAppFirewall.
type GetWebAppFirewallArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
	WebAppFirewallId string `pulumi:"webAppFirewallId"`
}

// A collection of values returned by getWebAppFirewall.
type GetWebAppFirewallResult struct {
	// Type of the WebAppFirewall, as example LOAD_BALANCER.
	BackendType string `pulumi:"backendType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// WebAppFirewall display name, can be renamed.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppFirewallPolicy is attached to.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The current state of the WebAppFirewall.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the WebAppFirewall was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the WebAppFirewall was updated. An RFC3339 formatted datetime string.
	TimeUpdated      string `pulumi:"timeUpdated"`
	WebAppFirewallId string `pulumi:"webAppFirewallId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
	WebAppFirewallPolicyId string `pulumi:"webAppFirewallPolicyId"`
}

func GetWebAppFirewallOutput(ctx *pulumi.Context, args GetWebAppFirewallOutputArgs, opts ...pulumi.InvokeOption) GetWebAppFirewallResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetWebAppFirewallResult, error) {
			args := v.(GetWebAppFirewallArgs)
			r, err := GetWebAppFirewall(ctx, &args, opts...)
			var s GetWebAppFirewallResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetWebAppFirewallResultOutput)
}

// A collection of arguments for invoking getWebAppFirewall.
type GetWebAppFirewallOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
	WebAppFirewallId pulumi.StringInput `pulumi:"webAppFirewallId"`
}

func (GetWebAppFirewallOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWebAppFirewallArgs)(nil)).Elem()
}

// A collection of values returned by getWebAppFirewall.
type GetWebAppFirewallResultOutput struct{ *pulumi.OutputState }

func (GetWebAppFirewallResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWebAppFirewallResult)(nil)).Elem()
}

func (o GetWebAppFirewallResultOutput) ToGetWebAppFirewallResultOutput() GetWebAppFirewallResultOutput {
	return o
}

func (o GetWebAppFirewallResultOutput) ToGetWebAppFirewallResultOutputWithContext(ctx context.Context) GetWebAppFirewallResultOutput {
	return o
}

// Type of the WebAppFirewall, as example LOAD_BALANCER.
func (o GetWebAppFirewallResultOutput) BackendType() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.BackendType }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetWebAppFirewallResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o GetWebAppFirewallResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// WebAppFirewall display name, can be renamed.
func (o GetWebAppFirewallResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o GetWebAppFirewallResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppFirewall.
func (o GetWebAppFirewallResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
func (o GetWebAppFirewallResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppFirewallPolicy is attached to.
func (o GetWebAppFirewallResultOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The current state of the WebAppFirewall.
func (o GetWebAppFirewallResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetWebAppFirewallResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time the WebAppFirewall was created. An RFC3339 formatted datetime string.
func (o GetWebAppFirewallResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the WebAppFirewall was updated. An RFC3339 formatted datetime string.
func (o GetWebAppFirewallResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func (o GetWebAppFirewallResultOutput) WebAppFirewallId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.WebAppFirewallId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppFirewallPolicy, which is attached to the resource.
func (o GetWebAppFirewallResultOutput) WebAppFirewallPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWebAppFirewallResult) string { return v.WebAppFirewallPolicyId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetWebAppFirewallResultOutput{})
}