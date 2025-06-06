// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Security Policy Deployment resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a security policy deployment by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetSecurityPolicyDeployment(ctx, &datasafe.GetSecurityPolicyDeploymentArgs{
//				SecurityPolicyDeploymentId: testSecurityPolicyDeploymentOciDataSafeSecurityPolicyDeployment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSecurityPolicyDeployment(ctx *pulumi.Context, args *LookupSecurityPolicyDeploymentArgs, opts ...pulumi.InvokeOption) (*LookupSecurityPolicyDeploymentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSecurityPolicyDeploymentResult
	err := ctx.Invoke("oci:DataSafe/getSecurityPolicyDeployment:getSecurityPolicyDeployment", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityPolicyDeployment.
type LookupSecurityPolicyDeploymentArgs struct {
	// The OCID of the security policy deployment resource.
	SecurityPolicyDeploymentId string `pulumi:"securityPolicyDeploymentId"`
}

// A collection of values returned by getSecurityPolicyDeployment.
type LookupSecurityPolicyDeploymentResult struct {
	// The OCID of the compartment containing the security policy deployment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the security policy deployment.
	Description string `pulumi:"description"`
	// The display name of the security policy deployment.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the security policy deployment.
	Id string `pulumi:"id"`
	// Details about the current state of the security policy deployment in Data Safe.
	LifecycleDetails           string `pulumi:"lifecycleDetails"`
	SecurityPolicyDeploymentId string `pulumi:"securityPolicyDeploymentId"`
	// The OCID of the security policy corresponding to the security policy deployment.
	SecurityPolicyId string `pulumi:"securityPolicyId"`
	// The current state of the security policy deployment.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The OCID of the target where the security policy is deployed.
	TargetId string `pulumi:"targetId"`
	// The time that the security policy deployment was created, in the format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupSecurityPolicyDeploymentOutput(ctx *pulumi.Context, args LookupSecurityPolicyDeploymentOutputArgs, opts ...pulumi.InvokeOption) LookupSecurityPolicyDeploymentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupSecurityPolicyDeploymentResultOutput, error) {
			args := v.(LookupSecurityPolicyDeploymentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSecurityPolicyDeployment:getSecurityPolicyDeployment", args, LookupSecurityPolicyDeploymentResultOutput{}, options).(LookupSecurityPolicyDeploymentResultOutput), nil
		}).(LookupSecurityPolicyDeploymentResultOutput)
}

// A collection of arguments for invoking getSecurityPolicyDeployment.
type LookupSecurityPolicyDeploymentOutputArgs struct {
	// The OCID of the security policy deployment resource.
	SecurityPolicyDeploymentId pulumi.StringInput `pulumi:"securityPolicyDeploymentId"`
}

func (LookupSecurityPolicyDeploymentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecurityPolicyDeploymentArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityPolicyDeployment.
type LookupSecurityPolicyDeploymentResultOutput struct{ *pulumi.OutputState }

func (LookupSecurityPolicyDeploymentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecurityPolicyDeploymentResult)(nil)).Elem()
}

func (o LookupSecurityPolicyDeploymentResultOutput) ToLookupSecurityPolicyDeploymentResultOutput() LookupSecurityPolicyDeploymentResultOutput {
	return o
}

func (o LookupSecurityPolicyDeploymentResultOutput) ToLookupSecurityPolicyDeploymentResultOutputWithContext(ctx context.Context) LookupSecurityPolicyDeploymentResultOutput {
	return o
}

// The OCID of the compartment containing the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o LookupSecurityPolicyDeploymentResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupSecurityPolicyDeploymentResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.Id }).(pulumi.StringOutput)
}

// Details about the current state of the security policy deployment in Data Safe.
func (o LookupSecurityPolicyDeploymentResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o LookupSecurityPolicyDeploymentResultOutput) SecurityPolicyDeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.SecurityPolicyDeploymentId }).(pulumi.StringOutput)
}

// The OCID of the security policy corresponding to the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) SecurityPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.SecurityPolicyId }).(pulumi.StringOutput)
}

// The current state of the security policy deployment.
func (o LookupSecurityPolicyDeploymentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupSecurityPolicyDeploymentResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The OCID of the target where the security policy is deployed.
func (o LookupSecurityPolicyDeploymentResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// The time that the security policy deployment was created, in the format defined by RFC3339.
func (o LookupSecurityPolicyDeploymentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The last date and time the security policy deployment was updated, in the format defined by RFC3339.
func (o LookupSecurityPolicyDeploymentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecurityPolicyDeploymentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSecurityPolicyDeploymentResultOutput{})
}
