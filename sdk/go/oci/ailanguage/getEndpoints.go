// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ailanguage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
//
// Returns a list of Endpoints.
func GetEndpoints(ctx *pulumi.Context, args *GetEndpointsArgs, opts ...pulumi.InvokeOption) (*GetEndpointsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetEndpointsResult
	err := ctx.Invoke("oci:AiLanguage/getEndpoints:getEndpoints", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getEndpoints.
type GetEndpointsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string              `pulumi:"displayName"`
	Filters     []GetEndpointsFilter `pulumi:"filters"`
	// Unique identifier endpoint OCID of an endpoint that is immutable on creation.
	Id *string `pulumi:"id"`
	// The ID of the trained model for which to list the endpoints.
	ModelId *string `pulumi:"modelId"`
	// The ID of the project for which to list the objects.
	ProjectId *string `pulumi:"projectId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getEndpoints.
type GetEndpointsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the endpoint compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The list of endpoint_collection.
	EndpointCollections []GetEndpointsEndpointCollection `pulumi:"endpointCollections"`
	Filters             []GetEndpointsFilter             `pulumi:"filters"`
	// Unique identifier endpoint OCID of an endpoint that is immutable on creation.
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
	ModelId *string `pulumi:"modelId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
	ProjectId *string `pulumi:"projectId"`
	// The state of the endpoint.
	State *string `pulumi:"state"`
}

func GetEndpointsOutput(ctx *pulumi.Context, args GetEndpointsOutputArgs, opts ...pulumi.InvokeOption) GetEndpointsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetEndpointsResult, error) {
			args := v.(GetEndpointsArgs)
			r, err := GetEndpoints(ctx, &args, opts...)
			var s GetEndpointsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetEndpointsResultOutput)
}

// A collection of arguments for invoking getEndpoints.
type GetEndpointsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput        `pulumi:"displayName"`
	Filters     GetEndpointsFilterArrayInput `pulumi:"filters"`
	// Unique identifier endpoint OCID of an endpoint that is immutable on creation.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// The ID of the trained model for which to list the endpoints.
	ModelId pulumi.StringPtrInput `pulumi:"modelId"`
	// The ID of the project for which to list the objects.
	ProjectId pulumi.StringPtrInput `pulumi:"projectId"`
	// <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetEndpointsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEndpointsArgs)(nil)).Elem()
}

// A collection of values returned by getEndpoints.
type GetEndpointsResultOutput struct{ *pulumi.OutputState }

func (GetEndpointsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEndpointsResult)(nil)).Elem()
}

func (o GetEndpointsResultOutput) ToGetEndpointsResultOutput() GetEndpointsResultOutput {
	return o
}

func (o GetEndpointsResultOutput) ToGetEndpointsResultOutputWithContext(ctx context.Context) GetEndpointsResultOutput {
	return o
}

func (o GetEndpointsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetEndpointsResult] {
	return pulumix.Output[GetEndpointsResult]{
		OutputState: o.OutputState,
	}
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the endpoint compartment.
func (o GetEndpointsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetEndpointsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
func (o GetEndpointsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEndpointsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of endpoint_collection.
func (o GetEndpointsResultOutput) EndpointCollections() GetEndpointsEndpointCollectionArrayOutput {
	return o.ApplyT(func(v GetEndpointsResult) []GetEndpointsEndpointCollection { return v.EndpointCollections }).(GetEndpointsEndpointCollectionArrayOutput)
}

func (o GetEndpointsResultOutput) Filters() GetEndpointsFilterArrayOutput {
	return o.ApplyT(func(v GetEndpointsResult) []GetEndpointsFilter { return v.Filters }).(GetEndpointsFilterArrayOutput)
}

// Unique identifier endpoint OCID of an endpoint that is immutable on creation.
func (o GetEndpointsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEndpointsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
func (o GetEndpointsResultOutput) ModelId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEndpointsResult) *string { return v.ModelId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
func (o GetEndpointsResultOutput) ProjectId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEndpointsResult) *string { return v.ProjectId }).(pulumi.StringPtrOutput)
}

// The state of the endpoint.
func (o GetEndpointsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEndpointsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetEndpointsResultOutput{})
}