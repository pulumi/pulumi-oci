// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func GetShape(ctx *pulumi.Context, args *GetShapeArgs, opts ...pulumi.InvokeOption) (*GetShapeResult, error) {
	var rv GetShapeResult
	err := ctx.Invoke("oci:Core/getShape:getShape", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getShape.
type GetShapeArgs struct {
	AvailabilityDomain *string          `pulumi:"availabilityDomain"`
	CompartmentId      string           `pulumi:"compartmentId"`
	Filters            []GetShapeFilter `pulumi:"filters"`
	ImageId            *string          `pulumi:"imageId"`
}

// A collection of values returned by getShape.
type GetShapeResult struct {
	AvailabilityDomain *string          `pulumi:"availabilityDomain"`
	CompartmentId      string           `pulumi:"compartmentId"`
	Filters            []GetShapeFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id      string          `pulumi:"id"`
	ImageId *string         `pulumi:"imageId"`
	Shapes  []GetShapeShape `pulumi:"shapes"`
}

func GetShapeOutput(ctx *pulumi.Context, args GetShapeOutputArgs, opts ...pulumi.InvokeOption) GetShapeResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetShapeResult, error) {
			args := v.(GetShapeArgs)
			r, err := GetShape(ctx, &args, opts...)
			var s GetShapeResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetShapeResultOutput)
}

// A collection of arguments for invoking getShape.
type GetShapeOutputArgs struct {
	AvailabilityDomain pulumi.StringPtrInput    `pulumi:"availabilityDomain"`
	CompartmentId      pulumi.StringInput       `pulumi:"compartmentId"`
	Filters            GetShapeFilterArrayInput `pulumi:"filters"`
	ImageId            pulumi.StringPtrInput    `pulumi:"imageId"`
}

func (GetShapeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetShapeArgs)(nil)).Elem()
}

// A collection of values returned by getShape.
type GetShapeResultOutput struct{ *pulumi.OutputState }

func (GetShapeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetShapeResult)(nil)).Elem()
}

func (o GetShapeResultOutput) ToGetShapeResultOutput() GetShapeResultOutput {
	return o
}

func (o GetShapeResultOutput) ToGetShapeResultOutputWithContext(ctx context.Context) GetShapeResultOutput {
	return o
}

func (o GetShapeResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetShapeResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetShapeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetShapeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetShapeResultOutput) Filters() GetShapeFilterArrayOutput {
	return o.ApplyT(func(v GetShapeResult) []GetShapeFilter { return v.Filters }).(GetShapeFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetShapeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetShapeResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetShapeResultOutput) ImageId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetShapeResult) *string { return v.ImageId }).(pulumi.StringPtrOutput)
}

func (o GetShapeResultOutput) Shapes() GetShapeShapeArrayOutput {
	return o.ApplyT(func(v GetShapeResult) []GetShapeShape { return v.Shapes }).(GetShapeShapeArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetShapeResultOutput{})
}