// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Shapes in Oracle Cloud Infrastructure MySQL Database service.
//
// Gets a list of the shapes you can use to create a new MySQL DB System.
// The shape determines the resources allocated to the DB System:
// CPU cores and memory for VM shapes; CPU cores, memory and
// storage for non-VM (or bare metal) shapes.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Mysql.GetShapes(ctx, &mysql.GetShapesArgs{
//				CompartmentId:      _var.Compartment_id,
//				AvailabilityDomain: pulumi.StringRef(_var.Shape_availability_domain),
//				IsSupportedFors:    _var.Shape_is_supported_for,
//				Name:               pulumi.StringRef(_var.Shape_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetShapes(ctx *pulumi.Context, args *GetShapesArgs, opts ...pulumi.InvokeOption) (*GetShapesResult, error) {
	var rv GetShapesResult
	err := ctx.Invoke("oci:Mysql/getShapes:getShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getShapes.
type GetShapesArgs struct {
	// The name of the Availability Domain.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string            `pulumi:"compartmentId"`
	Filters       []GetShapesFilter `pulumi:"filters"`
	// Return shapes that are supported by the service feature.
	IsSupportedFors []string `pulumi:"isSupportedFors"`
	// Name
	Name *string `pulumi:"name"`
}

// A collection of values returned by getShapes.
type GetShapesResult struct {
	AvailabilityDomain *string           `pulumi:"availabilityDomain"`
	CompartmentId      string            `pulumi:"compartmentId"`
	Filters            []GetShapesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// What service features the shape is supported for.
	IsSupportedFors []string `pulumi:"isSupportedFors"`
	// The name of the shape used for the DB System.
	Name *string `pulumi:"name"`
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
	// The name of the Availability Domain.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput        `pulumi:"compartmentId"`
	Filters       GetShapesFilterArrayInput `pulumi:"filters"`
	// Return shapes that are supported by the service feature.
	IsSupportedFors pulumi.StringArrayInput `pulumi:"isSupportedFors"`
	// Name
	Name pulumi.StringPtrInput `pulumi:"name"`
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

// What service features the shape is supported for.
func (o GetShapesResultOutput) IsSupportedFors() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetShapesResult) []string { return v.IsSupportedFors }).(pulumi.StringArrayOutput)
}

// The name of the shape used for the DB System.
func (o GetShapesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetShapesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of shapes.
func (o GetShapesResultOutput) Shapes() GetShapesShapeArrayOutput {
	return o.ApplyT(func(v GetShapesResult) []GetShapesShape { return v.Shapes }).(GetShapesShapeArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetShapesResultOutput{})
}