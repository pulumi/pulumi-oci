// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudmigrations

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Migration Plans in Oracle Cloud Infrastructure Cloud Migrations service.
//
// Returns a list of migration plans.
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
//			_, err := CloudMigrations.GetMigrationPlans(ctx, &cloudmigrations.GetMigrationPlansArgs{
//				CompartmentId:   pulumi.StringRef(_var.Compartment_id),
//				DisplayName:     pulumi.StringRef(_var.Migration_plan_display_name),
//				MigrationId:     pulumi.StringRef(oci_cloud_migrations_migration.Test_migration.Id),
//				MigrationPlanId: pulumi.StringRef(oci_cloud_migrations_migration_plan.Test_migration_plan.Id),
//				State:           pulumi.StringRef(_var.Migration_plan_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMigrationPlans(ctx *pulumi.Context, args *GetMigrationPlansArgs, opts ...pulumi.InvokeOption) (*GetMigrationPlansResult, error) {
	var rv GetMigrationPlansResult
	err := ctx.Invoke("oci:CloudMigrations/getMigrationPlans:getMigrationPlans", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMigrationPlans.
type GetMigrationPlansArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire given display name.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetMigrationPlansFilter `pulumi:"filters"`
	// Unique migration identifier
	MigrationId *string `pulumi:"migrationId"`
	// Unique migration plan identifier
	MigrationPlanId *string `pulumi:"migrationPlanId"`
	// The current state of the migration plan.
	State *string `pulumi:"state"`
}

// A collection of values returned by getMigrationPlans.
type GetMigrationPlansResult struct {
	// The OCID of the compartment containing the migration plan.
	CompartmentId *string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetMigrationPlansFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the associated migration.
	MigrationId *string `pulumi:"migrationId"`
	// The list of migration_plan_collection.
	MigrationPlanCollections []GetMigrationPlansMigrationPlanCollection `pulumi:"migrationPlanCollections"`
	MigrationPlanId          *string                                    `pulumi:"migrationPlanId"`
	// The current state of the migration plan.
	State *string `pulumi:"state"`
}

func GetMigrationPlansOutput(ctx *pulumi.Context, args GetMigrationPlansOutputArgs, opts ...pulumi.InvokeOption) GetMigrationPlansResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMigrationPlansResult, error) {
			args := v.(GetMigrationPlansArgs)
			r, err := GetMigrationPlans(ctx, &args, opts...)
			var s GetMigrationPlansResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMigrationPlansResultOutput)
}

// A collection of arguments for invoking getMigrationPlans.
type GetMigrationPlansOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire given display name.
	DisplayName pulumi.StringPtrInput             `pulumi:"displayName"`
	Filters     GetMigrationPlansFilterArrayInput `pulumi:"filters"`
	// Unique migration identifier
	MigrationId pulumi.StringPtrInput `pulumi:"migrationId"`
	// Unique migration plan identifier
	MigrationPlanId pulumi.StringPtrInput `pulumi:"migrationPlanId"`
	// The current state of the migration plan.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMigrationPlansOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationPlansArgs)(nil)).Elem()
}

// A collection of values returned by getMigrationPlans.
type GetMigrationPlansResultOutput struct{ *pulumi.OutputState }

func (GetMigrationPlansResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMigrationPlansResult)(nil)).Elem()
}

func (o GetMigrationPlansResultOutput) ToGetMigrationPlansResultOutput() GetMigrationPlansResultOutput {
	return o
}

func (o GetMigrationPlansResultOutput) ToGetMigrationPlansResultOutputWithContext(ctx context.Context) GetMigrationPlansResultOutput {
	return o
}

// The OCID of the compartment containing the migration plan.
func (o GetMigrationPlansResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetMigrationPlansResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetMigrationPlansResultOutput) Filters() GetMigrationPlansFilterArrayOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) []GetMigrationPlansFilter { return v.Filters }).(GetMigrationPlansFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMigrationPlansResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the associated migration.
func (o GetMigrationPlansResultOutput) MigrationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) *string { return v.MigrationId }).(pulumi.StringPtrOutput)
}

// The list of migration_plan_collection.
func (o GetMigrationPlansResultOutput) MigrationPlanCollections() GetMigrationPlansMigrationPlanCollectionArrayOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) []GetMigrationPlansMigrationPlanCollection {
		return v.MigrationPlanCollections
	}).(GetMigrationPlansMigrationPlanCollectionArrayOutput)
}

func (o GetMigrationPlansResultOutput) MigrationPlanId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) *string { return v.MigrationPlanId }).(pulumi.StringPtrOutput)
}

// The current state of the migration plan.
func (o GetMigrationPlansResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMigrationPlansResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMigrationPlansResultOutput{})
}