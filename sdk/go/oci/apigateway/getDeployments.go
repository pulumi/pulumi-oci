// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deployments in Oracle Cloud Infrastructure API Gateway service.
//
// Returns a list of deployments.
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
//			_, err := apigateway.GetDeployments(ctx, &apigateway.GetDeploymentsArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(deploymentDisplayName),
//				GatewayId:     pulumi.StringRef(testGateway.Id),
//				State:         pulumi.StringRef(deploymentState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDeployments(ctx *pulumi.Context, args *GetDeploymentsArgs, opts ...pulumi.InvokeOption) (*GetDeploymentsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDeploymentsResult
	err := ctx.Invoke("oci:ApiGateway/getDeployments:getDeployments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeployments.
type GetDeploymentsArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetDeploymentsFilter `pulumi:"filters"`
	// Filter deployments by the gateway ocid.
	GatewayId *string `pulumi:"gatewayId"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State *string `pulumi:"state"`
}

// A collection of values returned by getDeployments.
type GetDeploymentsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of deployment_collection.
	DeploymentCollections []GetDeploymentsDeploymentCollection `pulumi:"deploymentCollections"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetDeploymentsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	GatewayId *string `pulumi:"gatewayId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the deployment.
	State *string `pulumi:"state"`
}

func GetDeploymentsOutput(ctx *pulumi.Context, args GetDeploymentsOutputArgs, opts ...pulumi.InvokeOption) GetDeploymentsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDeploymentsResultOutput, error) {
			args := v.(GetDeploymentsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApiGateway/getDeployments:getDeployments", args, GetDeploymentsResultOutput{}, options).(GetDeploymentsResultOutput), nil
		}).(GetDeploymentsResultOutput)
}

// A collection of arguments for invoking getDeployments.
type GetDeploymentsOutputArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput          `pulumi:"displayName"`
	Filters     GetDeploymentsFilterArrayInput `pulumi:"filters"`
	// Filter deployments by the gateway ocid.
	GatewayId pulumi.StringPtrInput `pulumi:"gatewayId"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDeploymentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentsArgs)(nil)).Elem()
}

// A collection of values returned by getDeployments.
type GetDeploymentsResultOutput struct{ *pulumi.OutputState }

func (GetDeploymentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeploymentsResult)(nil)).Elem()
}

func (o GetDeploymentsResultOutput) ToGetDeploymentsResultOutput() GetDeploymentsResultOutput {
	return o
}

func (o GetDeploymentsResultOutput) ToGetDeploymentsResultOutputWithContext(ctx context.Context) GetDeploymentsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
func (o GetDeploymentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of deployment_collection.
func (o GetDeploymentsResultOutput) DeploymentCollections() GetDeploymentsDeploymentCollectionArrayOutput {
	return o.ApplyT(func(v GetDeploymentsResult) []GetDeploymentsDeploymentCollection { return v.DeploymentCollections }).(GetDeploymentsDeploymentCollectionArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o GetDeploymentsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDeploymentsResultOutput) Filters() GetDeploymentsFilterArrayOutput {
	return o.ApplyT(func(v GetDeploymentsResult) []GetDeploymentsFilter { return v.Filters }).(GetDeploymentsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
func (o GetDeploymentsResultOutput) GatewayId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentsResult) *string { return v.GatewayId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDeploymentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDeploymentsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the deployment.
func (o GetDeploymentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeploymentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeploymentsResultOutput{})
}
