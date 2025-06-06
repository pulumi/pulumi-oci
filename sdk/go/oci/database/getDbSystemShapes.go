// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Db System Shapes in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the shapes that can be used to launch a new DB system. The shape determines resources to allocate to the DB system - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetDbSystemShapes(ctx, &database.GetDbSystemShapesArgs{
//				CompartmentId:      compartmentId,
//				AvailabilityDomain: pulumi.StringRef(dbSystemShapeAvailabilityDomain),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDbSystemShapes(ctx *pulumi.Context, args *GetDbSystemShapesArgs, opts ...pulumi.InvokeOption) (*GetDbSystemShapesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDbSystemShapesResult
	err := ctx.Invoke("oci:Database/getDbSystemShapes:getDbSystemShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbSystemShapes.
type GetDbSystemShapesArgs struct {
	// The name of the Availability Domain.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string                    `pulumi:"compartmentId"`
	Filters       []GetDbSystemShapesFilter `pulumi:"filters"`
}

// A collection of values returned by getDbSystemShapes.
type GetDbSystemShapesResult struct {
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	CompartmentId      string  `pulumi:"compartmentId"`
	// The list of db_system_shapes.
	DbSystemShapes []GetDbSystemShapesDbSystemShape `pulumi:"dbSystemShapes"`
	Filters        []GetDbSystemShapesFilter        `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetDbSystemShapesOutput(ctx *pulumi.Context, args GetDbSystemShapesOutputArgs, opts ...pulumi.InvokeOption) GetDbSystemShapesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDbSystemShapesResultOutput, error) {
			args := v.(GetDbSystemShapesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getDbSystemShapes:getDbSystemShapes", args, GetDbSystemShapesResultOutput{}, options).(GetDbSystemShapesResultOutput), nil
		}).(GetDbSystemShapesResultOutput)
}

// A collection of arguments for invoking getDbSystemShapes.
type GetDbSystemShapesOutputArgs struct {
	// The name of the Availability Domain.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput                `pulumi:"compartmentId"`
	Filters       GetDbSystemShapesFilterArrayInput `pulumi:"filters"`
}

func (GetDbSystemShapesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbSystemShapesArgs)(nil)).Elem()
}

// A collection of values returned by getDbSystemShapes.
type GetDbSystemShapesResultOutput struct{ *pulumi.OutputState }

func (GetDbSystemShapesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDbSystemShapesResult)(nil)).Elem()
}

func (o GetDbSystemShapesResultOutput) ToGetDbSystemShapesResultOutput() GetDbSystemShapesResultOutput {
	return o
}

func (o GetDbSystemShapesResultOutput) ToGetDbSystemShapesResultOutputWithContext(ctx context.Context) GetDbSystemShapesResultOutput {
	return o
}

func (o GetDbSystemShapesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDbSystemShapesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

func (o GetDbSystemShapesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbSystemShapesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of db_system_shapes.
func (o GetDbSystemShapesResultOutput) DbSystemShapes() GetDbSystemShapesDbSystemShapeArrayOutput {
	return o.ApplyT(func(v GetDbSystemShapesResult) []GetDbSystemShapesDbSystemShape { return v.DbSystemShapes }).(GetDbSystemShapesDbSystemShapeArrayOutput)
}

func (o GetDbSystemShapesResultOutput) Filters() GetDbSystemShapesFilterArrayOutput {
	return o.ApplyT(func(v GetDbSystemShapesResult) []GetDbSystemShapesFilter { return v.Filters }).(GetDbSystemShapesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDbSystemShapesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDbSystemShapesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDbSystemShapesResultOutput{})
}
