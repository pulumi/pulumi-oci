// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed My Sql Database Inbound Replications in Oracle Cloud Infrastructure Database Management service.
//
// Retrieves information about the inbound replications of a specific MySQL server.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemanagement.GetManagedMySqlDatabaseInboundReplications(ctx, &databasemanagement.GetManagedMySqlDatabaseInboundReplicationsArgs{
//				ManagedMySqlDatabaseId: testManagedMySqlDatabase.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedMySqlDatabaseInboundReplications(ctx *pulumi.Context, args *GetManagedMySqlDatabaseInboundReplicationsArgs, opts ...pulumi.InvokeOption) (*GetManagedMySqlDatabaseInboundReplicationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagedMySqlDatabaseInboundReplicationsResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedMySqlDatabaseInboundReplications:getManagedMySqlDatabaseInboundReplications", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedMySqlDatabaseInboundReplications.
type GetManagedMySqlDatabaseInboundReplicationsArgs struct {
	Filters []GetManagedMySqlDatabaseInboundReplicationsFilter `pulumi:"filters"`
	// The OCID of the Managed MySQL Database.
	ManagedMySqlDatabaseId string `pulumi:"managedMySqlDatabaseId"`
}

// A collection of values returned by getManagedMySqlDatabaseInboundReplications.
type GetManagedMySqlDatabaseInboundReplicationsResult struct {
	Filters []GetManagedMySqlDatabaseInboundReplicationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                     string `pulumi:"id"`
	ManagedMySqlDatabaseId string `pulumi:"managedMySqlDatabaseId"`
	// The list of managed_my_sql_database_inbound_replication_collection.
	ManagedMySqlDatabaseInboundReplicationCollections []GetManagedMySqlDatabaseInboundReplicationsManagedMySqlDatabaseInboundReplicationCollection `pulumi:"managedMySqlDatabaseInboundReplicationCollections"`
}

func GetManagedMySqlDatabaseInboundReplicationsOutput(ctx *pulumi.Context, args GetManagedMySqlDatabaseInboundReplicationsOutputArgs, opts ...pulumi.InvokeOption) GetManagedMySqlDatabaseInboundReplicationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagedMySqlDatabaseInboundReplicationsResultOutput, error) {
			args := v.(GetManagedMySqlDatabaseInboundReplicationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getManagedMySqlDatabaseInboundReplications:getManagedMySqlDatabaseInboundReplications", args, GetManagedMySqlDatabaseInboundReplicationsResultOutput{}, options).(GetManagedMySqlDatabaseInboundReplicationsResultOutput), nil
		}).(GetManagedMySqlDatabaseInboundReplicationsResultOutput)
}

// A collection of arguments for invoking getManagedMySqlDatabaseInboundReplications.
type GetManagedMySqlDatabaseInboundReplicationsOutputArgs struct {
	Filters GetManagedMySqlDatabaseInboundReplicationsFilterArrayInput `pulumi:"filters"`
	// The OCID of the Managed MySQL Database.
	ManagedMySqlDatabaseId pulumi.StringInput `pulumi:"managedMySqlDatabaseId"`
}

func (GetManagedMySqlDatabaseInboundReplicationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabaseInboundReplicationsArgs)(nil)).Elem()
}

// A collection of values returned by getManagedMySqlDatabaseInboundReplications.
type GetManagedMySqlDatabaseInboundReplicationsResultOutput struct{ *pulumi.OutputState }

func (GetManagedMySqlDatabaseInboundReplicationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabaseInboundReplicationsResult)(nil)).Elem()
}

func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) ToGetManagedMySqlDatabaseInboundReplicationsResultOutput() GetManagedMySqlDatabaseInboundReplicationsResultOutput {
	return o
}

func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) ToGetManagedMySqlDatabaseInboundReplicationsResultOutputWithContext(ctx context.Context) GetManagedMySqlDatabaseInboundReplicationsResultOutput {
	return o
}

func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) Filters() GetManagedMySqlDatabaseInboundReplicationsFilterArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseInboundReplicationsResult) []GetManagedMySqlDatabaseInboundReplicationsFilter {
		return v.Filters
	}).(GetManagedMySqlDatabaseInboundReplicationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseInboundReplicationsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) ManagedMySqlDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseInboundReplicationsResult) string { return v.ManagedMySqlDatabaseId }).(pulumi.StringOutput)
}

// The list of managed_my_sql_database_inbound_replication_collection.
func (o GetManagedMySqlDatabaseInboundReplicationsResultOutput) ManagedMySqlDatabaseInboundReplicationCollections() GetManagedMySqlDatabaseInboundReplicationsManagedMySqlDatabaseInboundReplicationCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseInboundReplicationsResult) []GetManagedMySqlDatabaseInboundReplicationsManagedMySqlDatabaseInboundReplicationCollection {
		return v.ManagedMySqlDatabaseInboundReplicationCollections
	}).(GetManagedMySqlDatabaseInboundReplicationsManagedMySqlDatabaseInboundReplicationCollectionArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedMySqlDatabaseInboundReplicationsResultOutput{})
}
