// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed My Sql Database High Availability Members in Oracle Cloud Infrastructure Database Management service.
//
// Information about high availability members of a specific MySQL server's replication group.
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
//			_, err := databasemanagement.GetManagedMySqlDatabaseHighAvailabilityMembers(ctx, &databasemanagement.GetManagedMySqlDatabaseHighAvailabilityMembersArgs{
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
func GetManagedMySqlDatabaseHighAvailabilityMembers(ctx *pulumi.Context, args *GetManagedMySqlDatabaseHighAvailabilityMembersArgs, opts ...pulumi.InvokeOption) (*GetManagedMySqlDatabaseHighAvailabilityMembersResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagedMySqlDatabaseHighAvailabilityMembersResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedMySqlDatabaseHighAvailabilityMembers:getManagedMySqlDatabaseHighAvailabilityMembers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedMySqlDatabaseHighAvailabilityMembers.
type GetManagedMySqlDatabaseHighAvailabilityMembersArgs struct {
	Filters []GetManagedMySqlDatabaseHighAvailabilityMembersFilter `pulumi:"filters"`
	// The OCID of the Managed MySQL Database.
	ManagedMySqlDatabaseId string `pulumi:"managedMySqlDatabaseId"`
}

// A collection of values returned by getManagedMySqlDatabaseHighAvailabilityMembers.
type GetManagedMySqlDatabaseHighAvailabilityMembersResult struct {
	Filters []GetManagedMySqlDatabaseHighAvailabilityMembersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of managed_my_sql_database_high_availability_member_collection.
	ManagedMySqlDatabaseHighAvailabilityMemberCollections []GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollection `pulumi:"managedMySqlDatabaseHighAvailabilityMemberCollections"`
	ManagedMySqlDatabaseId                                string                                                                                               `pulumi:"managedMySqlDatabaseId"`
}

func GetManagedMySqlDatabaseHighAvailabilityMembersOutput(ctx *pulumi.Context, args GetManagedMySqlDatabaseHighAvailabilityMembersOutputArgs, opts ...pulumi.InvokeOption) GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput, error) {
			args := v.(GetManagedMySqlDatabaseHighAvailabilityMembersArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getManagedMySqlDatabaseHighAvailabilityMembers:getManagedMySqlDatabaseHighAvailabilityMembers", args, GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput{}, options).(GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput), nil
		}).(GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput)
}

// A collection of arguments for invoking getManagedMySqlDatabaseHighAvailabilityMembers.
type GetManagedMySqlDatabaseHighAvailabilityMembersOutputArgs struct {
	Filters GetManagedMySqlDatabaseHighAvailabilityMembersFilterArrayInput `pulumi:"filters"`
	// The OCID of the Managed MySQL Database.
	ManagedMySqlDatabaseId pulumi.StringInput `pulumi:"managedMySqlDatabaseId"`
}

func (GetManagedMySqlDatabaseHighAvailabilityMembersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabaseHighAvailabilityMembersArgs)(nil)).Elem()
}

// A collection of values returned by getManagedMySqlDatabaseHighAvailabilityMembers.
type GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput struct{ *pulumi.OutputState }

func (GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedMySqlDatabaseHighAvailabilityMembersResult)(nil)).Elem()
}

func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) ToGetManagedMySqlDatabaseHighAvailabilityMembersResultOutput() GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput {
	return o
}

func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) ToGetManagedMySqlDatabaseHighAvailabilityMembersResultOutputWithContext(ctx context.Context) GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput {
	return o
}

func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) Filters() GetManagedMySqlDatabaseHighAvailabilityMembersFilterArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseHighAvailabilityMembersResult) []GetManagedMySqlDatabaseHighAvailabilityMembersFilter {
		return v.Filters
	}).(GetManagedMySqlDatabaseHighAvailabilityMembersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseHighAvailabilityMembersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of managed_my_sql_database_high_availability_member_collection.
func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) ManagedMySqlDatabaseHighAvailabilityMemberCollections() GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseHighAvailabilityMembersResult) []GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollection {
		return v.ManagedMySqlDatabaseHighAvailabilityMemberCollections
	}).(GetManagedMySqlDatabaseHighAvailabilityMembersManagedMySqlDatabaseHighAvailabilityMemberCollectionArrayOutput)
}

func (o GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput) ManagedMySqlDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedMySqlDatabaseHighAvailabilityMembersResult) string { return v.ManagedMySqlDatabaseId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedMySqlDatabaseHighAvailabilityMembersResultOutput{})
}
