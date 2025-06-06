// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Deploy Environments in Oracle Cloud Infrastructure Devops service.
//
// Returns a list of deployment environments.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/devops"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := devops.GetDeployEnvironments(ctx, &devops.GetDeployEnvironmentsArgs{
//				CompartmentId: pulumi.StringRef(compartmentId),
//				DisplayName:   pulumi.StringRef(deployEnvironmentDisplayName),
//				Id:            pulumi.StringRef(deployEnvironmentId),
//				ProjectId:     pulumi.StringRef(testProject.Id),
//				State:         pulumi.StringRef(deployEnvironmentState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDeployEnvironments(ctx *pulumi.Context, args *GetDeployEnvironmentsArgs, opts ...pulumi.InvokeOption) (*GetDeployEnvironmentsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDeployEnvironmentsResult
	err := ctx.Invoke("oci:DevOps/getDeployEnvironments:getDeployEnvironments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeployEnvironments.
type GetDeployEnvironmentsArgs struct {
	// The OCID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetDeployEnvironmentsFilter `pulumi:"filters"`
	// Unique identifier or OCID for listing a single resource by ID.
	Id *string `pulumi:"id"`
	// unique project identifier
	ProjectId *string `pulumi:"projectId"`
	// A filter to return only DeployEnvironments that matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDeployEnvironments.
type GetDeployEnvironmentsResult struct {
	// The OCID of a compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of deploy_environment_collection.
	DeployEnvironmentCollections []GetDeployEnvironmentsDeployEnvironmentCollection `pulumi:"deployEnvironmentCollections"`
	// Deployment environment display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
	DisplayName *string                       `pulumi:"displayName"`
	Filters     []GetDeployEnvironmentsFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation.
	Id *string `pulumi:"id"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the deployment environment.
	State *string `pulumi:"state"`
}

func GetDeployEnvironmentsOutput(ctx *pulumi.Context, args GetDeployEnvironmentsOutputArgs, opts ...pulumi.InvokeOption) GetDeployEnvironmentsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDeployEnvironmentsResultOutput, error) {
			args := v.(GetDeployEnvironmentsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DevOps/getDeployEnvironments:getDeployEnvironments", args, GetDeployEnvironmentsResultOutput{}, options).(GetDeployEnvironmentsResultOutput), nil
		}).(GetDeployEnvironmentsResultOutput)
}

// A collection of arguments for invoking getDeployEnvironments.
type GetDeployEnvironmentsOutputArgs struct {
	// The OCID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                 `pulumi:"displayName"`
	Filters     GetDeployEnvironmentsFilterArrayInput `pulumi:"filters"`
	// Unique identifier or OCID for listing a single resource by ID.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// unique project identifier
	ProjectId pulumi.StringPtrInput `pulumi:"projectId"`
	// A filter to return only DeployEnvironments that matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDeployEnvironmentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeployEnvironmentsArgs)(nil)).Elem()
}

// A collection of values returned by getDeployEnvironments.
type GetDeployEnvironmentsResultOutput struct{ *pulumi.OutputState }

func (GetDeployEnvironmentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDeployEnvironmentsResult)(nil)).Elem()
}

func (o GetDeployEnvironmentsResultOutput) ToGetDeployEnvironmentsResultOutput() GetDeployEnvironmentsResultOutput {
	return o
}

func (o GetDeployEnvironmentsResultOutput) ToGetDeployEnvironmentsResultOutputWithContext(ctx context.Context) GetDeployEnvironmentsResultOutput {
	return o
}

// The OCID of a compartment.
func (o GetDeployEnvironmentsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The list of deploy_environment_collection.
func (o GetDeployEnvironmentsResultOutput) DeployEnvironmentCollections() GetDeployEnvironmentsDeployEnvironmentCollectionArrayOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) []GetDeployEnvironmentsDeployEnvironmentCollection {
		return v.DeployEnvironmentCollections
	}).(GetDeployEnvironmentsDeployEnvironmentCollectionArrayOutput)
}

// Deployment environment display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
func (o GetDeployEnvironmentsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetDeployEnvironmentsResultOutput) Filters() GetDeployEnvironmentsFilterArrayOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) []GetDeployEnvironmentsFilter { return v.Filters }).(GetDeployEnvironmentsFilterArrayOutput)
}

// Unique identifier that is immutable on creation.
func (o GetDeployEnvironmentsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The OCID of a project.
func (o GetDeployEnvironmentsResultOutput) ProjectId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) *string { return v.ProjectId }).(pulumi.StringPtrOutput)
}

// The current state of the deployment environment.
func (o GetDeployEnvironmentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDeployEnvironmentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDeployEnvironmentsResultOutput{})
}
