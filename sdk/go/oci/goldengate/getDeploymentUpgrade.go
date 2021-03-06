// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Deployment Upgrade resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Retrieves a deployment upgrade.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/GoldenGate"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := GoldenGate.GetDeploymentUpgrade(ctx, &goldengate.GetDeploymentUpgradeArgs{
// 			DeploymentUpgradeId: oci_golden_gate_deployment_upgrade.Test_deployment_upgrade.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetDeploymentUpgrade(ctx *pulumi.Context, args *GetDeploymentUpgradeArgs, opts ...pulumi.InvokeOption) (*GetDeploymentUpgradeResult, error) {
	var rv GetDeploymentUpgradeResult
	err := ctx.Invoke("oci:GoldenGate/getDeploymentUpgrade:getDeploymentUpgrade", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeploymentUpgrade.
type GetDeploymentUpgradeArgs struct {
	// A unique Deployment Upgrade identifier.
	DeploymentUpgradeId string `pulumi:"deploymentUpgradeId"`
}

// A collection of values returned by getDeploymentUpgrade.
type GetDeploymentUpgradeResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId string `pulumi:"compartmentId"`
	// Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
	DeploymentId        string `pulumi:"deploymentId"`
	DeploymentUpgradeId string `pulumi:"deploymentUpgradeId"`
	// The type of the deployment upgrade: MANUAL or AUTOMATIC
	DeploymentUpgradeType string `pulumi:"deploymentUpgradeType"`
	// Metadata about this specific object.
	Description string `pulumi:"description"`
	// An object's Display Name.
	DisplayName string `pulumi:"displayName"`
	// A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Possible GGS lifecycle sub-states.
	LifecycleSubState string `pulumi:"lifecycleSubState"`
	// Version of OGG
	OggVersion string `pulumi:"oggVersion"`
	// Possible lifecycle states.
	State string `pulumi:"state"`
	// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the request was finished. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeFinished string `pulumi:"timeFinished"`
	// The date and time the request was started. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeStarted string `pulumi:"timeStarted"`
	// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func GetDeploymentUpgradeOutput(ctx *pulumi.Context, args GetDeploymentUpgradeOutputArgs, opts ...pulumi.InvokeOption) GetDeploymentUpgradeResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDeploymentUpgradeResult, error) {
			args := v.(GetDeploymentUpgradeArgs)
			r, err := GetDeploymentUpgrade(ctx, &args, opts...)
			var s GetDeploymentUpgradeResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDeploymentUpgradeResultOutput)
}

// A collection of arguments for invoking getDeploymentUpgrade.
type GetDeploymentUpgradeOutputArgs struct {
	// A unique Deployment Upgrade identifier.
	DeploymentUpgradeId pulumi.StringInput `pulumi:"deploymentUpgradeId"`
}

func (GetDeploymentUpgradeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentUpgradeArgs)(nil)).Elem()
}

// A collection of values returned by getDeploymentUpgrade.
type GetDeploymentUpgradeResultOutput struct{ *pulumi.OutputState }

func (GetDeploymentUpgradeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentUpgradeResult)(nil)).Elem()
}

func (o GetDeploymentUpgradeResultOutput) ToGetDeploymentUpgradeResultOutput() GetDeploymentUpgradeResultOutput {
	return o
}

func (o GetDeploymentUpgradeResultOutput) ToGetDeploymentUpgradeResultOutputWithContext(ctx context.Context) GetDeploymentUpgradeResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
func (o GetDeploymentUpgradeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Tags defined for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o GetDeploymentUpgradeResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
func (o GetDeploymentUpgradeResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

func (o GetDeploymentUpgradeResultOutput) DeploymentUpgradeId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.DeploymentUpgradeId }).(pulumi.StringOutput)
}

// The type of the deployment upgrade: MANUAL or AUTOMATIC
func (o GetDeploymentUpgradeResultOutput) DeploymentUpgradeType() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.DeploymentUpgradeType }).(pulumi.StringOutput)
}

// Metadata about this specific object.
func (o GetDeploymentUpgradeResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.Description }).(pulumi.StringOutput)
}

// An object's Display Name.
func (o GetDeploymentUpgradeResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// A simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o GetDeploymentUpgradeResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDeploymentUpgradeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.Id }).(pulumi.StringOutput)
}

// Describes the object's current state in detail. For example, it can be used to provide actionable information for a resource in a Failed state.
func (o GetDeploymentUpgradeResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Possible GGS lifecycle sub-states.
func (o GetDeploymentUpgradeResultOutput) LifecycleSubState() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.LifecycleSubState }).(pulumi.StringOutput)
}

// Version of OGG
func (o GetDeploymentUpgradeResultOutput) OggVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.OggVersion }).(pulumi.StringOutput)
}

// Possible lifecycle states.
func (o GetDeploymentUpgradeResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.State }).(pulumi.StringOutput)
}

// The system tags associated with this resource, if any. The system tags are set by Oracle Cloud Infrastructure services. Each key is predefined and scoped to namespaces.  For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{orcl-cloud: {free-tier-retain: true}}`
func (o GetDeploymentUpgradeResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o GetDeploymentUpgradeResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the request was finished. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o GetDeploymentUpgradeResultOutput) TimeFinished() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.TimeFinished }).(pulumi.StringOutput)
}

// The date and time the request was started. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o GetDeploymentUpgradeResultOutput) TimeStarted() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.TimeStarted }).(pulumi.StringOutput)
}

// The time the resource was last updated. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o GetDeploymentUpgradeResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradeResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeploymentUpgradeResultOutput{})
}
