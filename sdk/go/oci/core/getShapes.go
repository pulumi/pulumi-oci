// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Shapes in Oracle Cloud Infrastructure Core service.
//
// Lists the shapes that can be used to launch an instance within the specified compartment. You can
// filter the list by compatibility with a specific image.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Core.GetShapes(ctx, &core.GetShapesArgs{
// 			CompartmentId:      _var.Compartment_id,
// 			AvailabilityDomain: pulumi.StringRef(_var.Shape_availability_domain),
// 			ImageId:            pulumi.StringRef(oci_core_image.Test_image.Id),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetShapes(ctx *pulumi.Context, args *GetShapesArgs, opts ...pulumi.InvokeOption) (*GetShapesResult, error) {
	var rv GetShapesResult
	err := ctx.Invoke("oci:Core/getShapes:getShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getShapes.
type GetShapesArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetShapesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
	ImageId *string `pulumi:"imageId"`
}

// A collection of values returned by getShapes.
type GetShapesResult struct {
	AvailabilityDomain *string           `pulumi:"availabilityDomain"`
	CompartmentId      string            `pulumi:"compartmentId"`
	Filters            []GetShapesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id      string  `pulumi:"id"`
	ImageId *string `pulumi:"imageId"`
	// The list of shapes.
	Shapes []GetShapesShape `pulumi:"shapes"`
}

func GetShapesOutput(ctx *pulumi.Context, args GetShapesOutputArgs, opts ...pulumi.InvokeOption) GetShapesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetShapesResult, error) {
			args := v.(GetShapesArgs)
			r, err := GetShapes(ctx, &args, opts...)
			var s GetShapesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetShapesResultOutput)
}

// A collection of arguments for invoking getShapes.
type GetShapesOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput        `pulumi:"compartmentId"`
	Filters       GetShapesFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
	ImageId pulumi.StringPtrInput `pulumi:"imageId"`
}

func (GetShapesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetShapesArgs)(nil)).Elem()
}

// A collection of values returned by getShapes.
type GetShapesResultOutput struct{ *pulumi.OutputState }

func (GetShapesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetShapesResult)(nil)).Elem()
}

func (o GetShapesResultOutput) ToGetShapesResultOutput() GetShapesResultOutput {
	return o
}

func (o GetShapesResultOutput) ToGetShapesResultOutputWithContext(ctx context.Context) GetShapesResultOutput {
	return o
}

func (o GetShapesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetShapesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetShapesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetShapesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetShapesResultOutput) Filters() GetShapesFilterArrayOutput {
	return o.ApplyT(func(v GetShapesResult) []GetShapesFilter { return v.Filters }).(GetShapesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetShapesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetShapesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetShapesResultOutput) ImageId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetShapesResult) *string { return v.ImageId }).(pulumi.StringPtrOutput)
}

// The list of shapes.
func (o GetShapesResultOutput) Shapes() GetShapesShapeArrayOutput {
	return o.ApplyT(func(v GetShapesResult) []GetShapesShape { return v.Shapes }).(GetShapesShapeArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetShapesResultOutput{})
}
