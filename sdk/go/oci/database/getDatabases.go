// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Databases in Oracle Cloud Infrastructure Database service.
//
// Gets a list of the databases in the specified Database Home.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.GetDatabases(ctx, &database.GetDatabasesArgs{
//				CompartmentId: _var.Compartment_id,
//				DbHomeId:      pulumi.StringRef(oci_database_db_home.Test_db_home.Id),
//				DbName:        pulumi.StringRef(_var.Database_db_name),
//				State:         pulumi.StringRef(_var.Database_state),
//				SystemId:      pulumi.StringRef(oci_database_system.Test_system.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDatabases(ctx *pulumi.Context, args *GetDatabasesArgs, opts ...pulumi.InvokeOption) (*GetDatabasesResult, error) {
	var rv GetDatabasesResult
	err := ctx.Invoke("oci:Database/getDatabases:getDatabases", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDatabases.
type GetDatabasesArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). *Note: Either `dbHomeId` or `systemId` is required to make the LIST API call.
	DbHomeId *string `pulumi:"dbHomeId"`
	// A filter to return only resources that match the entire database name given. The match is not case sensitive.
	DbName  *string              `pulumi:"dbName"`
	Filters []GetDatabasesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata DB system that you want to filter the database results by. Applies only to Exadata DB systems.
	SystemId *string `pulumi:"systemId"`
}

// A collection of values returned by getDatabases.
type GetDatabasesResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of databases.
	Databases []GetDatabasesDatabase `pulumi:"databases"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
	DbHomeId *string `pulumi:"dbHomeId"`
	// The database name.
	DbName  *string              `pulumi:"dbName"`
	Filters []GetDatabasesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the database.
	State    *string `pulumi:"state"`
	SystemId *string `pulumi:"systemId"`
}

func GetDatabasesOutput(ctx *pulumi.Context, args GetDatabasesOutputArgs, opts ...pulumi.InvokeOption) GetDatabasesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDatabasesResult, error) {
			args := v.(GetDatabasesArgs)
			r, err := GetDatabases(ctx, &args, opts...)
			var s GetDatabasesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDatabasesResultOutput)
}

// A collection of arguments for invoking getDatabases.
type GetDatabasesOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A Database Home [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). *Note: Either `dbHomeId` or `systemId` is required to make the LIST API call.
	DbHomeId pulumi.StringPtrInput `pulumi:"dbHomeId"`
	// A filter to return only resources that match the entire database name given. The match is not case sensitive.
	DbName  pulumi.StringPtrInput        `pulumi:"dbName"`
	Filters GetDatabasesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata DB system that you want to filter the database results by. Applies only to Exadata DB systems.
	SystemId pulumi.StringPtrInput `pulumi:"systemId"`
}

func (GetDatabasesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabasesArgs)(nil)).Elem()
}

// A collection of values returned by getDatabases.
type GetDatabasesResultOutput struct{ *pulumi.OutputState }

func (GetDatabasesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDatabasesResult)(nil)).Elem()
}

func (o GetDatabasesResultOutput) ToGetDatabasesResultOutput() GetDatabasesResultOutput {
	return o
}

func (o GetDatabasesResultOutput) ToGetDatabasesResultOutputWithContext(ctx context.Context) GetDatabasesResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetDatabasesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabasesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of databases.
func (o GetDatabasesResultOutput) Databases() GetDatabasesDatabaseArrayOutput {
	return o.ApplyT(func(v GetDatabasesResult) []GetDatabasesDatabase { return v.Databases }).(GetDatabasesDatabaseArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Home.
func (o GetDatabasesResultOutput) DbHomeId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabasesResult) *string { return v.DbHomeId }).(pulumi.StringPtrOutput)
}

// The database name.
func (o GetDatabasesResultOutput) DbName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabasesResult) *string { return v.DbName }).(pulumi.StringPtrOutput)
}

func (o GetDatabasesResultOutput) Filters() GetDatabasesFilterArrayOutput {
	return o.ApplyT(func(v GetDatabasesResult) []GetDatabasesFilter { return v.Filters }).(GetDatabasesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetDatabasesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetDatabasesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the database.
func (o GetDatabasesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabasesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetDatabasesResultOutput) SystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDatabasesResult) *string { return v.SystemId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDatabasesResultOutput{})
}