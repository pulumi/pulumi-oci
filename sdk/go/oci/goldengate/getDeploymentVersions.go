// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deployment Versions in Oracle Cloud Infrastructure Golden Gate service.
//
// Returns the list of available deployment versions.
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
//			_, err := GoldenGate.GetDeploymentVersions(ctx, &goldengate.GetDeploymentVersionsArgs{
//				CompartmentId:  _var.Compartment_id,
//				DeploymentId:   pulumi.StringRef(oci_golden_gate_deployment.Test_deployment.Id),
//				DeploymentType: pulumi.StringRef(_var.Deployment_version_deployment_type),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDeploymentVersions(ctx *pulumi.Context, args *GetDeploymentVersionsArgs, opts ...pulumi.InvokeOption) (*GetDeploymentVersionsResult, error) {
	var rv GetDeploymentVersionsResult
	err := ctx.Invoke("oci:GoldenGate/getDeploymentVersions:getDeploymentVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeploymentVersions.
type GetDeploymentVersionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
	DeploymentId *string `pulumi:"deploymentId"`
	// The type of deployment, the value determines the exact 'type' of the service executed in the deployment. Default value is DATABASE_ORACLE.
	DeploymentType *string                       `pulumi:"deploymentType"`
	Filters        []GetDeploymentVersionsFilter `pulumi:"filters"`
}

// A collection of values returned by getDeploymentVersions.
type GetDeploymentVersionsResult struct {
	CompartmentId string  `pulumi:"compartmentId"`
	DeploymentId  *string `pulumi:"deploymentId"`
	// The type of deployment, the value determines the exact 'type' of service executed in the Deployment. NOTE: Use of the value 'OGG' is maintained for backward compatibility purposes.  Its use is discouraged in favor of the equivalent 'DATABASE_ORACLE' value.
	DeploymentType *string `pulumi:"deploymentType"`
	// The list of deployment_version_collection.
	DeploymentVersionCollections []GetDeploymentVersionsDeploymentVersionCollection `pulumi:"deploymentVersionCollections"`
	Filters                      []GetDeploymentVersionsFilter                      `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetDeploymentVersionsOutput(ctx *pulumi.Context, args GetDeploymentVersionsOutputArgs, opts ...pulumi.InvokeOption) GetDeploymentVersionsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDeploymentVersionsResult, error) {
			args := v.(GetDeploymentVersionsArgs)
			r, err := GetDeploymentVersions(ctx, &args, opts...)
			var s GetDeploymentVersionsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDeploymentVersionsResultOutput)
}

// A collection of arguments for invoking getDeploymentVersions.
type GetDeploymentVersionsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
	DeploymentId pulumi.StringPtrInput `pulumi:"deploymentId"`
	// The type of deployment, the value determines the exact 'type' of the service executed in the deployment. Default value is DATABASE_ORACLE.
	DeploymentType pulumi.StringPtrInput                 `pulumi:"deploymentType"`
	Filters        GetDeploymentVersionsFilterArrayInput `pulumi:"filters"`
}

func (GetDeploymentVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getDeploymentVersions.
type GetDeploymentVersionsResultOutput struct{ *pulumi.OutputState }

func (GetDeploymentVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentVersionsResult)(nil)).Elem()
}

func (o GetDeploymentVersionsResultOutput) ToGetDeploymentVersionsResultOutput() GetDeploymentVersionsResultOutput {
	return o
}

func (o GetDeploymentVersionsResultOutput) ToGetDeploymentVersionsResultOutputWithContext(ctx context.Context) GetDeploymentVersionsResultOutput {
	return o
}

func (o GetDeploymentVersionsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetDeploymentVersionsResultOutput) DeploymentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) *string { return v.DeploymentId }).(pulumi.StringPtrOutput)
}

// The type of deployment, the value determines the exact 'type' of service executed in the Deployment. NOTE: Use of the value 'OGG' is maintained for backward compatibility purposes.  Its use is discouraged in favor of the equivalent 'DATABASE_ORACLE' value.
func (o GetDeploymentVersionsResultOutput) DeploymentType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) *string { return v.DeploymentType }).(pulumi.StringPtrOutput)
}

// The list of deployment_version_collection.
func (o GetDeploymentVersionsResultOutput) DeploymentVersionCollections() GetDeploymentVersionsDeploymentVersionCollectionArrayOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) []GetDeploymentVersionsDeploymentVersionCollection {
		return v.DeploymentVersionCollections
	}).(GetDeploymentVersionsDeploymentVersionCollectionArrayOutput)
}

func (o GetDeploymentVersionsResultOutput) Filters() GetDeploymentVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) []GetDeploymentVersionsFilter { return v.Filters }).(GetDeploymentVersionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDeploymentVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeploymentVersionsResultOutput{})
}