// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed Database User Object Privileges in Oracle Cloud Infrastructure Database Management service.
//
// Gets the list of object privileges granted to a specific user.
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
//			_, err := DatabaseManagement.GetManagedDatabaseUserObjectPrivileges(ctx, &databasemanagement.GetManagedDatabaseUserObjectPrivilegesArgs{
//				ManagedDatabaseId: oci_database_management_managed_database.Test_managed_database.Id,
//				UserName:          oci_identity_user.Test_user.Name,
//				Name:              pulumi.StringRef(_var.Managed_database_user_object_privilege_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseUserObjectPrivileges(ctx *pulumi.Context, args *GetManagedDatabaseUserObjectPrivilegesArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseUserObjectPrivilegesResult, error) {
	var rv GetManagedDatabaseUserObjectPrivilegesResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseUserObjectPrivileges:getManagedDatabaseUserObjectPrivileges", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseUserObjectPrivileges.
type GetManagedDatabaseUserObjectPrivilegesArgs struct {
	Filters []GetManagedDatabaseUserObjectPrivilegesFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// A filter to return only resources that match the entire name.
	Name *string `pulumi:"name"`
	// The name of the user whose details are to be viewed.
	UserName string `pulumi:"userName"`
}

// A collection of values returned by getManagedDatabaseUserObjectPrivileges.
type GetManagedDatabaseUserObjectPrivilegesResult struct {
	Filters []GetManagedDatabaseUserObjectPrivilegesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                string `pulumi:"id"`
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The name of the privilege on the object.
	Name *string `pulumi:"name"`
	// The list of object_privilege_collection.
	ObjectPrivilegeCollections []GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection `pulumi:"objectPrivilegeCollections"`
	UserName                   string                                                            `pulumi:"userName"`
}

func GetManagedDatabaseUserObjectPrivilegesOutput(ctx *pulumi.Context, args GetManagedDatabaseUserObjectPrivilegesOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseUserObjectPrivilegesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseUserObjectPrivilegesResult, error) {
			args := v.(GetManagedDatabaseUserObjectPrivilegesArgs)
			r, err := GetManagedDatabaseUserObjectPrivileges(ctx, &args, opts...)
			var s GetManagedDatabaseUserObjectPrivilegesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedDatabaseUserObjectPrivilegesResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseUserObjectPrivileges.
type GetManagedDatabaseUserObjectPrivilegesOutputArgs struct {
	Filters GetManagedDatabaseUserObjectPrivilegesFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
	// A filter to return only resources that match the entire name.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The name of the user whose details are to be viewed.
	UserName pulumi.StringInput `pulumi:"userName"`
}

func (GetManagedDatabaseUserObjectPrivilegesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseUserObjectPrivilegesArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseUserObjectPrivileges.
type GetManagedDatabaseUserObjectPrivilegesResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseUserObjectPrivilegesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseUserObjectPrivilegesResult)(nil)).Elem()
}

func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) ToGetManagedDatabaseUserObjectPrivilegesResultOutput() GetManagedDatabaseUserObjectPrivilegesResultOutput {
	return o
}

func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) ToGetManagedDatabaseUserObjectPrivilegesResultOutputWithContext(ctx context.Context) GetManagedDatabaseUserObjectPrivilegesResultOutput {
	return o
}

func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) Filters() GetManagedDatabaseUserObjectPrivilegesFilterArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) []GetManagedDatabaseUserObjectPrivilegesFilter {
		return v.Filters
	}).(GetManagedDatabaseUserObjectPrivilegesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// The name of the privilege on the object.
func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of object_privilege_collection.
func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) ObjectPrivilegeCollections() GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollectionArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) []GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollection {
		return v.ObjectPrivilegeCollections
	}).(GetManagedDatabaseUserObjectPrivilegesObjectPrivilegeCollectionArrayOutput)
}

func (o GetManagedDatabaseUserObjectPrivilegesResultOutput) UserName() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserObjectPrivilegesResult) string { return v.UserName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseUserObjectPrivilegesResultOutput{})
}