// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package usageproxy

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Resources in Oracle Cloud Infrastructure Usage Proxy service.
//
// Returns the resource details for a service
// > **Important**: Calls to this API will only succeed against the endpoint in the home region.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/UsageProxy"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := UsageProxy.GetResources(ctx, &usageproxy.GetResourcesArgs{
//				CompartmentId: _var.Compartment_id,
//				ServiceName:   oci_core_service.Test_service.Name,
//				EntitlementId: pulumi.StringRef(oci_usage_proxy_entitlement.Test_entitlement.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetResources(ctx *pulumi.Context, args *GetResourcesArgs, opts ...pulumi.InvokeOption) (*GetResourcesResult, error) {
	var rv GetResourcesResult
	err := ctx.Invoke("oci:UsageProxy/getResources:getResources", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResources.
type GetResourcesArgs struct {
	// The OCID of the root compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Subscription or entitlement Id.
	EntitlementId *string              `pulumi:"entitlementId"`
	Filters       []GetResourcesFilter `pulumi:"filters"`
	// Service Name.
	ServiceName string `pulumi:"serviceName"`
}

// A collection of values returned by getResources.
type GetResourcesResult struct {
	CompartmentId string               `pulumi:"compartmentId"`
	EntitlementId *string              `pulumi:"entitlementId"`
	Filters       []GetResourcesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of resources_collection.
	ResourcesCollections []GetResourcesResourcesCollection `pulumi:"resourcesCollections"`
	ServiceName          string                            `pulumi:"serviceName"`
}

func GetResourcesOutput(ctx *pulumi.Context, args GetResourcesOutputArgs, opts ...pulumi.InvokeOption) GetResourcesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetResourcesResult, error) {
			args := v.(GetResourcesArgs)
			r, err := GetResources(ctx, &args, opts...)
			var s GetResourcesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetResourcesResultOutput)
}

// A collection of arguments for invoking getResources.
type GetResourcesOutputArgs struct {
	// The OCID of the root compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Subscription or entitlement Id.
	EntitlementId pulumi.StringPtrInput        `pulumi:"entitlementId"`
	Filters       GetResourcesFilterArrayInput `pulumi:"filters"`
	// Service Name.
	ServiceName pulumi.StringInput `pulumi:"serviceName"`
}

func (GetResourcesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResourcesArgs)(nil)).Elem()
}

// A collection of values returned by getResources.
type GetResourcesResultOutput struct{ *pulumi.OutputState }

func (GetResourcesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetResourcesResult)(nil)).Elem()
}

func (o GetResourcesResultOutput) ToGetResourcesResultOutput() GetResourcesResultOutput {
	return o
}

func (o GetResourcesResultOutput) ToGetResourcesResultOutputWithContext(ctx context.Context) GetResourcesResultOutput {
	return o
}

func (o GetResourcesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourcesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetResourcesResultOutput) EntitlementId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetResourcesResult) *string { return v.EntitlementId }).(pulumi.StringPtrOutput)
}

func (o GetResourcesResultOutput) Filters() GetResourcesFilterArrayOutput {
	return o.ApplyT(func(v GetResourcesResult) []GetResourcesFilter { return v.Filters }).(GetResourcesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetResourcesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourcesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of resources_collection.
func (o GetResourcesResultOutput) ResourcesCollections() GetResourcesResourcesCollectionArrayOutput {
	return o.ApplyT(func(v GetResourcesResult) []GetResourcesResourcesCollection { return v.ResourcesCollections }).(GetResourcesResourcesCollectionArrayOutput)
}

func (o GetResourcesResultOutput) ServiceName() pulumi.StringOutput {
	return o.ApplyT(func(v GetResourcesResult) string { return v.ServiceName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetResourcesResultOutput{})
}