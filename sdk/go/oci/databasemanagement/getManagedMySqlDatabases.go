// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Managed My Sql Databases in Oracle Cloud Infrastructure Database Management service.
//
// Gets the list of Managed MySQL Databases in a specific compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DatabaseManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DatabaseManagement.GetManagedMySqlDatabases(ctx, &databasemanagement.GetManagedMySqlDatabasesArgs{
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
func GetManagedMySqlDatabases(ctx *pulumi.Context, args *GetManagedMySqlDatabasesArgs, opts ...pulumi.InvokeOption) (*GetManagedMySqlDatabasesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagedMySqlDatabasesResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedMySqlDatabases:getManagedMySqlDatabases", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedMySqlDatabases.
type GetManagedMySqlDatabasesArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string                           `pulumi:"compartmentId"`
	Filters       []GetManagedMySqlDatabasesFilter `pulumi:"filters"`
}

// A collection of values returned by getManagedMySqlDatabases.
type GetManagedMySqlDatabasesResult struct {
	// The OCID of the compartment.
	CompartmentId string                           `pulumi:"compartmentId"`
	Filters       []GetManagedMySqlDatabasesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of managed_my_sql_database_collection.
	ManagedMySqlDatabaseCollections []GetManagedMySqlDatabasesManagedMySqlDatabaseCollection `pulumi:"managedMySqlDatabaseCollections"`
}

func GetManagedMySqlDatabasesOutput(ctx *pulumi.Context, args GetManagedMySqlDatabasesOutputArgs, opts ...pulumi.InvokeOption) GetManagedMySqlDatabasesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedMySqlDatabasesResult, error) {
			args := v.(GetManagedMySqlDatabasesArgs)
			r, err := GetManagedMySqlDatabases(ctx, &args, opts...)
			var s GetManagedMySqlDatabasesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedMySqlDatabasesResultOutput)
}

// A collection of arguments for invoking getManagedMySqlDatabases.
type GetManagedMySqlDatabasesOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput                       `pulumi:"compartmentId"`
	Filters       GetManagedMySqlDatabasesFilterArrayInput `pulumi:"filters"`
}

func (GetManagedMySqlDatabasesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabasesArgs)(nil)).Elem()
}

// A collection of values returned by getManagedMySqlDatabases.
type GetManagedMySqlDatabasesResultOutput struct{ *pulumi.OutputState }

func (GetManagedMySqlDatabasesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabasesResult)(nil)).Elem()
}

func (o GetManagedMySqlDatabasesResultOutput) ToGetManagedMySqlDatabasesResultOutput() GetManagedMySqlDatabasesResultOutput {
	return o
}

func (o GetManagedMySqlDatabasesResultOutput) ToGetManagedMySqlDatabasesResultOutputWithContext(ctx context.Context) GetManagedMySqlDatabasesResultOutput {
	return o
}

func (o GetManagedMySqlDatabasesResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetManagedMySqlDatabasesResult] {
	return pulumix.Output[GetManagedMySqlDatabasesResult]{
		OutputState: o.OutputState,
	}
}

// The OCID of the compartment.
func (o GetManagedMySqlDatabasesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabasesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetManagedMySqlDatabasesResultOutput) Filters() GetManagedMySqlDatabasesFilterArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabasesResult) []GetManagedMySqlDatabasesFilter { return v.Filters }).(GetManagedMySqlDatabasesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedMySqlDatabasesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabasesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of managed_my_sql_database_collection.
func (o GetManagedMySqlDatabasesResultOutput) ManagedMySqlDatabaseCollections() GetManagedMySqlDatabasesManagedMySqlDatabaseCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabasesResult) []GetManagedMySqlDatabasesManagedMySqlDatabaseCollection {
		return v.ManagedMySqlDatabaseCollections
	}).(GetManagedMySqlDatabasesManagedMySqlDatabaseCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedMySqlDatabasesResultOutput{})
}