// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerinstances

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Container Instance Shapes in Oracle Cloud Infrastructure Container Instances service.
//
// Get a list of shapes for creating Container Instances and their details.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ContainerInstances"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ContainerInstances.GetContainerInstanceShapes(ctx, &containerinstances.GetContainerInstanceShapesArgs{
//				CompartmentId:      _var.Compartment_id,
//				AvailabilityDomain: pulumi.StringRef(_var.Container_instance_shape_availability_domain),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetContainerInstanceShapes(ctx *pulumi.Context, args *GetContainerInstanceShapesArgs, opts ...pulumi.InvokeOption) (*GetContainerInstanceShapesResult, error) {
	var rv GetContainerInstanceShapesResult
	err := ctx.Invoke("oci:ContainerInstances/getContainerInstanceShapes:getContainerInstanceShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getContainerInstanceShapes.
type GetContainerInstanceShapesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The ID of the compartment in which to list resources.
	CompartmentId string                             `pulumi:"compartmentId"`
	Filters       []GetContainerInstanceShapesFilter `pulumi:"filters"`
}

// A collection of values returned by getContainerInstanceShapes.
type GetContainerInstanceShapesResult struct {
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	CompartmentId      string  `pulumi:"compartmentId"`
	// The list of container_instance_shape_collection.
	ContainerInstanceShapeCollections []GetContainerInstanceShapesContainerInstanceShapeCollection `pulumi:"containerInstanceShapeCollections"`
	Filters                           []GetContainerInstanceShapesFilter                           `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetContainerInstanceShapesOutput(ctx *pulumi.Context, args GetContainerInstanceShapesOutputArgs, opts ...pulumi.InvokeOption) GetContainerInstanceShapesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetContainerInstanceShapesResult, error) {
			args := v.(GetContainerInstanceShapesArgs)
			r, err := GetContainerInstanceShapes(ctx, &args, opts...)
			var s GetContainerInstanceShapesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetContainerInstanceShapesResultOutput)
}

// A collection of arguments for invoking getContainerInstanceShapes.
type GetContainerInstanceShapesOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput                         `pulumi:"compartmentId"`
	Filters       GetContainerInstanceShapesFilterArrayInput `pulumi:"filters"`
}

func (GetContainerInstanceShapesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetContainerInstanceShapesArgs)(nil)).Elem()
}

// A collection of values returned by getContainerInstanceShapes.
type GetContainerInstanceShapesResultOutput struct{ *pulumi.OutputState }

func (GetContainerInstanceShapesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetContainerInstanceShapesResult)(nil)).Elem()
}

func (o GetContainerInstanceShapesResultOutput) ToGetContainerInstanceShapesResultOutput() GetContainerInstanceShapesResultOutput {
	return o
}

func (o GetContainerInstanceShapesResultOutput) ToGetContainerInstanceShapesResultOutputWithContext(ctx context.Context) GetContainerInstanceShapesResultOutput {
	return o
}

func (o GetContainerInstanceShapesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetContainerInstanceShapesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetContainerInstanceShapesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetContainerInstanceShapesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of container_instance_shape_collection.
func (o GetContainerInstanceShapesResultOutput) ContainerInstanceShapeCollections() GetContainerInstanceShapesContainerInstanceShapeCollectionArrayOutput {
	return o.ApplyT(func(v GetContainerInstanceShapesResult) []GetContainerInstanceShapesContainerInstanceShapeCollection {
		return v.ContainerInstanceShapeCollections
	}).(GetContainerInstanceShapesContainerInstanceShapeCollectionArrayOutput)
}

func (o GetContainerInstanceShapesResultOutput) Filters() GetContainerInstanceShapesFilterArrayOutput {
	return o.ApplyT(func(v GetContainerInstanceShapesResult) []GetContainerInstanceShapesFilter { return v.Filters }).(GetContainerInstanceShapesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetContainerInstanceShapesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetContainerInstanceShapesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetContainerInstanceShapesResultOutput{})
}