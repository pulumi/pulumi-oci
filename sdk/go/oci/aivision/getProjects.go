// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package aivision

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Projects in Oracle Cloud Infrastructure Ai Vision service.
//
// Returns a list of Projects.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/AiVision"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := AiVision.GetProjects(ctx, &aivision.GetProjectsArgs{
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				DisplayName:   pulumi.StringRef(_var.Project_display_name),
//				Id:            pulumi.StringRef(_var.Project_id),
//				State:         pulumi.StringRef(_var.Project_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProjects(ctx *pulumi.Context, args *GetProjectsArgs, opts ...pulumi.InvokeOption) (*GetProjectsResult, error) {
	var rv GetProjectsResult
	err := ctx.Invoke("oci:AiVision/getProjects:getProjects", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProjects.
type GetProjectsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetProjectsFilter `pulumi:"filters"`
	// unique Project identifier
	Id *string `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State *string `pulumi:"state"`
}

// A collection of values returned by getProjects.
type GetProjectsResult struct {
	// Compartment Identifier
	CompartmentId *string `pulumi:"compartmentId"`
	// Project Identifier, can be renamed
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetProjectsFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation
	Id *string `pulumi:"id"`
	// The list of project_collection.
	ProjectCollections []GetProjectsProjectCollection `pulumi:"projectCollections"`
	// The current state of the Project.
	State *string `pulumi:"state"`
}

func GetProjectsOutput(ctx *pulumi.Context, args GetProjectsOutputArgs, opts ...pulumi.InvokeOption) GetProjectsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetProjectsResult, error) {
			args := v.(GetProjectsArgs)
			r, err := GetProjects(ctx, &args, opts...)
			var s GetProjectsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetProjectsResultOutput)
}

// A collection of arguments for invoking getProjects.
type GetProjectsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput       `pulumi:"displayName"`
	Filters     GetProjectsFilterArrayInput `pulumi:"filters"`
	// unique Project identifier
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetProjectsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProjectsArgs)(nil)).Elem()
}

// A collection of values returned by getProjects.
type GetProjectsResultOutput struct{ *pulumi.OutputState }

func (GetProjectsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProjectsResult)(nil)).Elem()
}

func (o GetProjectsResultOutput) ToGetProjectsResultOutput() GetProjectsResultOutput {
	return o
}

func (o GetProjectsResultOutput) ToGetProjectsResultOutputWithContext(ctx context.Context) GetProjectsResultOutput {
	return o
}

// Compartment Identifier
func (o GetProjectsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProjectsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// Project Identifier, can be renamed
func (o GetProjectsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProjectsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetProjectsResultOutput) Filters() GetProjectsFilterArrayOutput {
	return o.ApplyT(func(v GetProjectsResult) []GetProjectsFilter { return v.Filters }).(GetProjectsFilterArrayOutput)
}

// Unique identifier that is immutable on creation
func (o GetProjectsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProjectsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The list of project_collection.
func (o GetProjectsResultOutput) ProjectCollections() GetProjectsProjectCollectionArrayOutput {
	return o.ApplyT(func(v GetProjectsResult) []GetProjectsProjectCollection { return v.ProjectCollections }).(GetProjectsProjectCollectionArrayOutput)
}

// The current state of the Project.
func (o GetProjectsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProjectsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetProjectsResultOutput{})
}