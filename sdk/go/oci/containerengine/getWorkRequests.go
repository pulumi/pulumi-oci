// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Work Requests in Oracle Cloud Infrastructure Container Engine service.
//
// List all work requests in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ContainerEngine"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ContainerEngine.GetWorkRequests(ctx, &containerengine.GetWorkRequestsArgs{
//				CompartmentId: _var.Compartment_id,
//				ClusterId:     pulumi.StringRef(oci_containerengine_cluster.Test_cluster.Id),
//				ResourceId:    pulumi.StringRef(oci_containerengine_resource.Test_resource.Id),
//				ResourceType:  pulumi.StringRef(_var.Work_request_resource_type),
//				Statuses:      _var.Work_request_status,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetWorkRequests(ctx *pulumi.Context, args *GetWorkRequestsArgs, opts ...pulumi.InvokeOption) (*GetWorkRequestsResult, error) {
	var rv GetWorkRequestsResult
	err := ctx.Invoke("oci:ContainerEngine/getWorkRequests:getWorkRequests", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWorkRequests.
type GetWorkRequestsArgs struct {
	// The OCID of the cluster.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment.
	CompartmentId string                  `pulumi:"compartmentId"`
	Filters       []GetWorkRequestsFilter `pulumi:"filters"`
	// The OCID of the resource associated with a work request
	ResourceId *string `pulumi:"resourceId"`
	// Type of the resource associated with a work request
	ResourceType *string `pulumi:"resourceType"`
	// A work request status to filter on. Can have multiple parameters of this name.
	Statuses []string `pulumi:"statuses"`
}

// A collection of values returned by getWorkRequests.
type GetWorkRequestsResult struct {
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of the compartment in which the work request exists.
	CompartmentId string                  `pulumi:"compartmentId"`
	Filters       []GetWorkRequestsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id           string  `pulumi:"id"`
	ResourceId   *string `pulumi:"resourceId"`
	ResourceType *string `pulumi:"resourceType"`
	// The current status of the work request.
	Statuses []string `pulumi:"statuses"`
	// The list of work_requests.
	WorkRequests []GetWorkRequestsWorkRequest `pulumi:"workRequests"`
}

func GetWorkRequestsOutput(ctx *pulumi.Context, args GetWorkRequestsOutputArgs, opts ...pulumi.InvokeOption) GetWorkRequestsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetWorkRequestsResult, error) {
			args := v.(GetWorkRequestsArgs)
			r, err := GetWorkRequests(ctx, &args, opts...)
			var s GetWorkRequestsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetWorkRequestsResultOutput)
}

// A collection of arguments for invoking getWorkRequests.
type GetWorkRequestsOutputArgs struct {
	// The OCID of the cluster.
	ClusterId pulumi.StringPtrInput `pulumi:"clusterId"`
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput              `pulumi:"compartmentId"`
	Filters       GetWorkRequestsFilterArrayInput `pulumi:"filters"`
	// The OCID of the resource associated with a work request
	ResourceId pulumi.StringPtrInput `pulumi:"resourceId"`
	// Type of the resource associated with a work request
	ResourceType pulumi.StringPtrInput `pulumi:"resourceType"`
	// A work request status to filter on. Can have multiple parameters of this name.
	Statuses pulumi.StringArrayInput `pulumi:"statuses"`
}

func (GetWorkRequestsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWorkRequestsArgs)(nil)).Elem()
}

// A collection of values returned by getWorkRequests.
type GetWorkRequestsResultOutput struct{ *pulumi.OutputState }

func (GetWorkRequestsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWorkRequestsResult)(nil)).Elem()
}

func (o GetWorkRequestsResultOutput) ToGetWorkRequestsResultOutput() GetWorkRequestsResultOutput {
	return o
}

func (o GetWorkRequestsResultOutput) ToGetWorkRequestsResultOutputWithContext(ctx context.Context) GetWorkRequestsResultOutput {
	return o
}

func (o GetWorkRequestsResultOutput) ClusterId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) *string { return v.ClusterId }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment in which the work request exists.
func (o GetWorkRequestsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetWorkRequestsResultOutput) Filters() GetWorkRequestsFilterArrayOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) []GetWorkRequestsFilter { return v.Filters }).(GetWorkRequestsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetWorkRequestsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetWorkRequestsResultOutput) ResourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) *string { return v.ResourceId }).(pulumi.StringPtrOutput)
}

func (o GetWorkRequestsResultOutput) ResourceType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) *string { return v.ResourceType }).(pulumi.StringPtrOutput)
}

// The current status of the work request.
func (o GetWorkRequestsResultOutput) Statuses() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) []string { return v.Statuses }).(pulumi.StringArrayOutput)
}

// The list of work_requests.
func (o GetWorkRequestsResultOutput) WorkRequests() GetWorkRequestsWorkRequestArrayOutput {
	return o.ApplyT(func(v GetWorkRequestsResult) []GetWorkRequestsWorkRequest { return v.WorkRequests }).(GetWorkRequestsWorkRequestArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetWorkRequestsResultOutput{})
}