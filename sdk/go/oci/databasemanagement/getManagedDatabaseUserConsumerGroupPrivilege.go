// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Database User Consumer Group Privilege resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the list of consumer group privileges granted to a specific user.
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
//			_, err := DatabaseManagement.GetManagedDatabaseUserConsumerGroupPrivilege(ctx, &databasemanagement.GetManagedDatabaseUserConsumerGroupPrivilegeArgs{
//				ManagedDatabaseId: oci_database_management_managed_database.Test_managed_database.Id,
//				UserName:          oci_identity_user.Test_user.Name,
//				Name:              pulumi.StringRef(_var.Managed_database_user_consumer_group_privilege_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedDatabaseUserConsumerGroupPrivilege(ctx *pulumi.Context, args *GetManagedDatabaseUserConsumerGroupPrivilegeArgs, opts ...pulumi.InvokeOption) (*GetManagedDatabaseUserConsumerGroupPrivilegeResult, error) {
	var rv GetManagedDatabaseUserConsumerGroupPrivilegeResult
	err := ctx.Invoke("oci:DatabaseManagement/getManagedDatabaseUserConsumerGroupPrivilege:getManagedDatabaseUserConsumerGroupPrivilege", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedDatabaseUserConsumerGroupPrivilege.
type GetManagedDatabaseUserConsumerGroupPrivilegeArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// A filter to return only resources that match the entire name.
	Name *string `pulumi:"name"`
	// The name of the user whose details are to be viewed.
	UserName string `pulumi:"userName"`
}

// A collection of values returned by getManagedDatabaseUserConsumerGroupPrivilege.
type GetManagedDatabaseUserConsumerGroupPrivilegeResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// An array of consumer group privileges.
	Items             []GetManagedDatabaseUserConsumerGroupPrivilegeItem `pulumi:"items"`
	ManagedDatabaseId string                                             `pulumi:"managedDatabaseId"`
	// The name of the granted consumer group privilege.
	Name     *string `pulumi:"name"`
	UserName string  `pulumi:"userName"`
}

func GetManagedDatabaseUserConsumerGroupPrivilegeOutput(ctx *pulumi.Context, args GetManagedDatabaseUserConsumerGroupPrivilegeOutputArgs, opts ...pulumi.InvokeOption) GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedDatabaseUserConsumerGroupPrivilegeResult, error) {
			args := v.(GetManagedDatabaseUserConsumerGroupPrivilegeArgs)
			r, err := GetManagedDatabaseUserConsumerGroupPrivilege(ctx, &args, opts...)
			var s GetManagedDatabaseUserConsumerGroupPrivilegeResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput)
}

// A collection of arguments for invoking getManagedDatabaseUserConsumerGroupPrivilege.
type GetManagedDatabaseUserConsumerGroupPrivilegeOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
	// A filter to return only resources that match the entire name.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The name of the user whose details are to be viewed.
	UserName pulumi.StringInput `pulumi:"userName"`
}

func (GetManagedDatabaseUserConsumerGroupPrivilegeOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseUserConsumerGroupPrivilegeArgs)(nil)).Elem()
}

// A collection of values returned by getManagedDatabaseUserConsumerGroupPrivilege.
type GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput struct{ *pulumi.OutputState }

func (GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedDatabaseUserConsumerGroupPrivilegeResult)(nil)).Elem()
}

func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) ToGetManagedDatabaseUserConsumerGroupPrivilegeResultOutput() GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput {
	return o
}

func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) ToGetManagedDatabaseUserConsumerGroupPrivilegeResultOutputWithContext(ctx context.Context) GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserConsumerGroupPrivilegeResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of consumer group privileges.
func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) Items() GetManagedDatabaseUserConsumerGroupPrivilegeItemArrayOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserConsumerGroupPrivilegeResult) []GetManagedDatabaseUserConsumerGroupPrivilegeItem {
		return v.Items
	}).(GetManagedDatabaseUserConsumerGroupPrivilegeItemArrayOutput)
}

func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserConsumerGroupPrivilegeResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// The name of the granted consumer group privilege.
func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserConsumerGroupPrivilegeResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput) UserName() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedDatabaseUserConsumerGroupPrivilegeResult) string { return v.UserName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedDatabaseUserConsumerGroupPrivilegeResultOutput{})
}