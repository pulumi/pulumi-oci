// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cross Connect Port Speed Shapes in Oracle Cloud Infrastructure Core service.
//
// Lists the available port speeds for cross-connects. You need this information
// so you can specify your desired port speed (that is, shape) when you create a
// cross-connect.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.GetCrossConnectPortSpeedShape(ctx, &core.GetCrossConnectPortSpeedShapeArgs{
//				CompartmentId: _var.Compartment_id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCrossConnectPortSpeedShape(ctx *pulumi.Context, args *GetCrossConnectPortSpeedShapeArgs, opts ...pulumi.InvokeOption) (*GetCrossConnectPortSpeedShapeResult, error) {
	var rv GetCrossConnectPortSpeedShapeResult
	err := ctx.Invoke("oci:Core/getCrossConnectPortSpeedShape:getCrossConnectPortSpeedShape", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCrossConnectPortSpeedShape.
type GetCrossConnectPortSpeedShapeArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                                `pulumi:"compartmentId"`
	Filters       []GetCrossConnectPortSpeedShapeFilter `pulumi:"filters"`
}

// A collection of values returned by getCrossConnectPortSpeedShape.
type GetCrossConnectPortSpeedShapeResult struct {
	CompartmentId string `pulumi:"compartmentId"`
	// The list of cross_connect_port_speed_shapes.
	CrossConnectPortSpeedShapes []GetCrossConnectPortSpeedShapeCrossConnectPortSpeedShape `pulumi:"crossConnectPortSpeedShapes"`
	Filters                     []GetCrossConnectPortSpeedShapeFilter                     `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetCrossConnectPortSpeedShapeOutput(ctx *pulumi.Context, args GetCrossConnectPortSpeedShapeOutputArgs, opts ...pulumi.InvokeOption) GetCrossConnectPortSpeedShapeResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetCrossConnectPortSpeedShapeResult, error) {
			args := v.(GetCrossConnectPortSpeedShapeArgs)
			r, err := GetCrossConnectPortSpeedShape(ctx, &args, opts...)
			var s GetCrossConnectPortSpeedShapeResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetCrossConnectPortSpeedShapeResultOutput)
}

// A collection of arguments for invoking getCrossConnectPortSpeedShape.
type GetCrossConnectPortSpeedShapeOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput                            `pulumi:"compartmentId"`
	Filters       GetCrossConnectPortSpeedShapeFilterArrayInput `pulumi:"filters"`
}

func (GetCrossConnectPortSpeedShapeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectPortSpeedShapeArgs)(nil)).Elem()
}

// A collection of values returned by getCrossConnectPortSpeedShape.
type GetCrossConnectPortSpeedShapeResultOutput struct{ *pulumi.OutputState }

func (GetCrossConnectPortSpeedShapeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCrossConnectPortSpeedShapeResult)(nil)).Elem()
}

func (o GetCrossConnectPortSpeedShapeResultOutput) ToGetCrossConnectPortSpeedShapeResultOutput() GetCrossConnectPortSpeedShapeResultOutput {
	return o
}

func (o GetCrossConnectPortSpeedShapeResultOutput) ToGetCrossConnectPortSpeedShapeResultOutputWithContext(ctx context.Context) GetCrossConnectPortSpeedShapeResultOutput {
	return o
}

func (o GetCrossConnectPortSpeedShapeResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectPortSpeedShapeResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of cross_connect_port_speed_shapes.
func (o GetCrossConnectPortSpeedShapeResultOutput) CrossConnectPortSpeedShapes() GetCrossConnectPortSpeedShapeCrossConnectPortSpeedShapeArrayOutput {
	return o.ApplyT(func(v GetCrossConnectPortSpeedShapeResult) []GetCrossConnectPortSpeedShapeCrossConnectPortSpeedShape {
		return v.CrossConnectPortSpeedShapes
	}).(GetCrossConnectPortSpeedShapeCrossConnectPortSpeedShapeArrayOutput)
}

func (o GetCrossConnectPortSpeedShapeResultOutput) Filters() GetCrossConnectPortSpeedShapeFilterArrayOutput {
	return o.ApplyT(func(v GetCrossConnectPortSpeedShapeResult) []GetCrossConnectPortSpeedShapeFilter { return v.Filters }).(GetCrossConnectPortSpeedShapeFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCrossConnectPortSpeedShapeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCrossConnectPortSpeedShapeResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCrossConnectPortSpeedShapeResultOutput{})
}