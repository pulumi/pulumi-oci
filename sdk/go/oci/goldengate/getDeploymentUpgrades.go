// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deployment Upgrades in Oracle Cloud Infrastructure Golden Gate service.
//
// Lists the Deployment Upgrades in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/GoldenGate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := GoldenGate.GetDeploymentUpgrades(ctx, &goldengate.GetDeploymentUpgradesArgs{
//				CompartmentId: _var.Compartment_id,
//				DeploymentId:  pulumi.StringRef(oci_golden_gate_deployment.Test_deployment.Id),
//				DisplayName:   pulumi.StringRef(_var.Deployment_upgrade_display_name),
//				State:         pulumi.StringRef(_var.Deployment_upgrade_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDeploymentUpgrades(ctx *pulumi.Context, args *GetDeploymentUpgradesArgs, opts ...pulumi.InvokeOption) (*GetDeploymentUpgradesResult, error) {
	var rv GetDeploymentUpgradesResult
	err := ctx.Invoke("oci:GoldenGate/getDeploymentUpgrades:getDeploymentUpgrades", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeploymentUpgrades.
type GetDeploymentUpgradesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// The ID of the deployment in which to list resources.
	DeploymentId *string `pulumi:"deploymentId"`
	// A filter to return only the resources that match the entire 'displayName' given.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetDeploymentUpgradesFilter `pulumi:"filters"`
	// A filter to return only the resources that match the 'lifecycleState' given.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDeploymentUpgrades.
type GetDeploymentUpgradesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
	DeploymentId *string `pulumi:"deploymentId"`
	// The list of deployment_upgrade_collection.
	DeploymentUpgradeCollections []GetDeploymentUpgradesDeploymentUpgradeCollection `pulumi:"deploymentUpgradeCollections"`
	// An object's Display Name.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetDeploymentUpgradesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Possible lifecycle states.
	State *string `pulumi:"state"`
}

func GetDeploymentUpgradesOutput(ctx *pulumi.Context, args GetDeploymentUpgradesOutputArgs, opts ...pulumi.InvokeOption) GetDeploymentUpgradesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDeploymentUpgradesResult, error) {
			args := v.(GetDeploymentUpgradesArgs)
			r, err := GetDeploymentUpgrades(ctx, &args, opts...)
			var s GetDeploymentUpgradesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDeploymentUpgradesResultOutput)
}

// A collection of arguments for invoking getDeploymentUpgrades.
type GetDeploymentUpgradesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The ID of the deployment in which to list resources.
	DeploymentId pulumi.StringPtrInput `pulumi:"deploymentId"`
	// A filter to return only the resources that match the entire 'displayName' given.
	DisplayName pulumi.StringPtrInput                 `pulumi:"displayName"`
	Filters     GetDeploymentUpgradesFilterArrayInput `pulumi:"filters"`
	// A filter to return only the resources that match the 'lifecycleState' given.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDeploymentUpgradesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentUpgradesArgs)(nil)).Elem()
}

// A collection of values returned by getDeploymentUpgrades.
type GetDeploymentUpgradesResultOutput struct{ *pulumi.OutputState }

func (GetDeploymentUpgradesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentUpgradesResult)(nil)).Elem()
}

func (o GetDeploymentUpgradesResultOutput) ToGetDeploymentUpgradesResultOutput() GetDeploymentUpgradesResultOutput {
	return o
}

func (o GetDeploymentUpgradesResultOutput) ToGetDeploymentUpgradesResultOutputWithContext(ctx context.Context) GetDeploymentUpgradesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment being referenced.
func (o GetDeploymentUpgradesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
func (o GetDeploymentUpgradesResultOutput) DeploymentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) *string { return v.DeploymentId }).(pulumi.StringPtrOutput)
}

// The list of deployment_upgrade_collection.
func (o GetDeploymentUpgradesResultOutput) DeploymentUpgradeCollections() GetDeploymentUpgradesDeploymentUpgradeCollectionArrayOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) []GetDeploymentUpgradesDeploymentUpgradeCollection {
		return v.DeploymentUpgradeCollections
	}).(GetDeploymentUpgradesDeploymentUpgradeCollectionArrayOutput)
}

// An object's Display Name.
func (o GetDeploymentUpgradesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDeploymentUpgradesResultOutput) Filters() GetDeploymentUpgradesFilterArrayOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) []GetDeploymentUpgradesFilter { return v.Filters }).(GetDeploymentUpgradesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDeploymentUpgradesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) string { return v.Id }).(pulumi.StringOutput)
}

// Possible lifecycle states.
func (o GetDeploymentUpgradesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentUpgradesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeploymentUpgradesResultOutput{})
}