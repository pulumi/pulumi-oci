// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudmigrations

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Migration Plan Available Shapes in Oracle Cloud Infrastructure Cloud Migrations service.
//
// List of shapes by parameters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/CloudMigrations"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := CloudMigrations.GetMigrationPlanAvailableShapes(ctx, &cloudmigrations.GetMigrationPlanAvailableShapesArgs{
//				MigrationPlanId:    oci_cloud_migrations_migration_plan.Test_migration_plan.Id,
//				AvailabilityDomain: pulumi.StringRef(_var.Migration_plan_available_shape_availability_domain),
//				CompartmentId:      pulumi.StringRef(_var.Compartment_id),
//				DvhHostId:          pulumi.StringRef(oci_cloud_migrations_dvh_host.Test_dvh_host.Id),
//				ReservedCapacityId: pulumi.StringRef(oci_cloud_migrations_reserved_capacity.Test_reserved_capacity.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMigrationPlanAvailableShapes(ctx *pulumi.Context, args *GetMigrationPlanAvailableShapesArgs, opts ...pulumi.InvokeOption) (*GetMigrationPlanAvailableShapesResult, error) {
	var rv GetMigrationPlanAvailableShapesResult
	err := ctx.Invoke("oci:CloudMigrations/getMigrationPlanAvailableShapes:getMigrationPlanAvailableShapes", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMigrationPlanAvailableShapes.
type GetMigrationPlanAvailableShapesArgs struct {
	// The availability domain in which to list resources.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// The ID of the Dvh in which to list resources.
	DvhHostId *string                                 `pulumi:"dvhHostId"`
	Filters   []GetMigrationPlanAvailableShapesFilter `pulumi:"filters"`
	// Unique migration plan identifier
	MigrationPlanId string `pulumi:"migrationPlanId"`
	// The reserved capacity ID for which to list resources.
	ReservedCapacityId *string `pulumi:"reservedCapacityId"`
}

// A collection of values returned by getMigrationPlanAvailableShapes.
type GetMigrationPlanAvailableShapesResult struct {
	// Availability domain of the shape.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The list of available_shapes_collection.
	AvailableShapesCollections []GetMigrationPlanAvailableShapesAvailableShapesCollection `pulumi:"availableShapesCollections"`
	CompartmentId              *string                                                    `pulumi:"compartmentId"`
	DvhHostId                  *string                                                    `pulumi:"dvhHostId"`
	Filters                    []GetMigrationPlanAvailableShapesFilter                    `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                 string  `pulumi:"id"`
	MigrationPlanId    string  `pulumi:"migrationPlanId"`
	ReservedCapacityId *string `pulumi:"reservedCapacityId"`
}

func GetMigrationPlanAvailableShapesOutput(ctx *pulumi.Context, args GetMigrationPlanAvailableShapesOutputArgs, opts ...pulumi.InvokeOption) GetMigrationPlanAvailableShapesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMigrationPlanAvailableShapesResult, error) {
			args := v.(GetMigrationPlanAvailableShapesArgs)
			r, err := GetMigrationPlanAvailableShapes(ctx, &args, opts...)
			var s GetMigrationPlanAvailableShapesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMigrationPlanAvailableShapesResultOutput)
}

// A collection of arguments for invoking getMigrationPlanAvailableShapes.
type GetMigrationPlanAvailableShapesOutputArgs struct {
	// The availability domain in which to list resources.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The ID of the Dvh in which to list resources.
	DvhHostId pulumi.StringPtrInput                           `pulumi:"dvhHostId"`
	Filters   GetMigrationPlanAvailableShapesFilterArrayInput `pulumi:"filters"`
	// Unique migration plan identifier
	MigrationPlanId pulumi.StringInput `pulumi:"migrationPlanId"`
	// The reserved capacity ID for which to list resources.
	ReservedCapacityId pulumi.StringPtrInput `pulumi:"reservedCapacityId"`
}

func (GetMigrationPlanAvailableShapesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationPlanAvailableShapesArgs)(nil)).Elem()
}

// A collection of values returned by getMigrationPlanAvailableShapes.
type GetMigrationPlanAvailableShapesResultOutput struct{ *pulumi.OutputState }

func (GetMigrationPlanAvailableShapesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationPlanAvailableShapesResult)(nil)).Elem()
}

func (o GetMigrationPlanAvailableShapesResultOutput) ToGetMigrationPlanAvailableShapesResultOutput() GetMigrationPlanAvailableShapesResultOutput {
	return o
}

func (o GetMigrationPlanAvailableShapesResultOutput) ToGetMigrationPlanAvailableShapesResultOutputWithContext(ctx context.Context) GetMigrationPlanAvailableShapesResultOutput {
	return o
}

// Availability domain of the shape.
func (o GetMigrationPlanAvailableShapesResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The list of available_shapes_collection.
func (o GetMigrationPlanAvailableShapesResultOutput) AvailableShapesCollections() GetMigrationPlanAvailableShapesAvailableShapesCollectionArrayOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) []GetMigrationPlanAvailableShapesAvailableShapesCollection {
		return v.AvailableShapesCollections
	}).(GetMigrationPlanAvailableShapesAvailableShapesCollectionArrayOutput)
}

func (o GetMigrationPlanAvailableShapesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetMigrationPlanAvailableShapesResultOutput) DvhHostId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) *string { return v.DvhHostId }).(pulumi.StringPtrOutput)
}

func (o GetMigrationPlanAvailableShapesResultOutput) Filters() GetMigrationPlanAvailableShapesFilterArrayOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) []GetMigrationPlanAvailableShapesFilter {
		return v.Filters
	}).(GetMigrationPlanAvailableShapesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMigrationPlanAvailableShapesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetMigrationPlanAvailableShapesResultOutput) MigrationPlanId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) string { return v.MigrationPlanId }).(pulumi.StringOutput)
}

func (o GetMigrationPlanAvailableShapesResultOutput) ReservedCapacityId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlanAvailableShapesResult) *string { return v.ReservedCapacityId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMigrationPlanAvailableShapesResultOutput{})
}