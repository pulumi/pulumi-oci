// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Managed Database Preferred Credential resource in Oracle Cloud Infrastructure Database Management service.
//
// Gets the preferred credential details for a Managed Database based on credentialName.
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
//			_, err := Database.GetManagedPreferredCredential(ctx, &database.GetManagedPreferredCredentialArgs{
//				CredentialName:    _var.Managed_database_preferred_credential_credential_name,
//				ManagedDatabaseId: oci_database_management_managed_database.Test_managed_database.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagedPreferredCredential(ctx *pulumi.Context, args *GetManagedPreferredCredentialArgs, opts ...pulumi.InvokeOption) (*GetManagedPreferredCredentialResult, error) {
	var rv GetManagedPreferredCredentialResult
	err := ctx.Invoke("oci:Database/getManagedPreferredCredential:getManagedPreferredCredential", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagedPreferredCredential.
type GetManagedPreferredCredentialArgs struct {
	// The name of the preferred credential.
	CredentialName string `pulumi:"credentialName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
}

// A collection of values returned by getManagedPreferredCredential.
type GetManagedPreferredCredentialResult struct {
	// The name of the preferred credential.
	CredentialName string `pulumi:"credentialName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Indicates whether the preferred credential is accessible.
	IsAccessible      bool   `pulumi:"isAccessible"`
	ManagedDatabaseId string `pulumi:"managedDatabaseId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Vault service secret that contains the database user password.
	PasswordSecretId string `pulumi:"passwordSecretId"`
	// The role of the database user.
	Role string `pulumi:"role"`
	// The status of the preferred credential.
	Status string `pulumi:"status"`
	// The type of preferred credential. Only 'BASIC' is supported currently.
	Type string `pulumi:"type"`
	// The user name used to connect to the database.
	UserName string `pulumi:"userName"`
}

func GetManagedPreferredCredentialOutput(ctx *pulumi.Context, args GetManagedPreferredCredentialOutputArgs, opts ...pulumi.InvokeOption) GetManagedPreferredCredentialResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetManagedPreferredCredentialResult, error) {
			args := v.(GetManagedPreferredCredentialArgs)
			r, err := GetManagedPreferredCredential(ctx, &args, opts...)
			var s GetManagedPreferredCredentialResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetManagedPreferredCredentialResultOutput)
}

// A collection of arguments for invoking getManagedPreferredCredential.
type GetManagedPreferredCredentialOutputArgs struct {
	// The name of the preferred credential.
	CredentialName pulumi.StringInput `pulumi:"credentialName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
	ManagedDatabaseId pulumi.StringInput `pulumi:"managedDatabaseId"`
}

func (GetManagedPreferredCredentialOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedPreferredCredentialArgs)(nil)).Elem()
}

// A collection of values returned by getManagedPreferredCredential.
type GetManagedPreferredCredentialResultOutput struct{ *pulumi.OutputState }

func (GetManagedPreferredCredentialResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagedPreferredCredentialResult)(nil)).Elem()
}

func (o GetManagedPreferredCredentialResultOutput) ToGetManagedPreferredCredentialResultOutput() GetManagedPreferredCredentialResultOutput {
	return o
}

func (o GetManagedPreferredCredentialResultOutput) ToGetManagedPreferredCredentialResultOutputWithContext(ctx context.Context) GetManagedPreferredCredentialResultOutput {
	return o
}

// The name of the preferred credential.
func (o GetManagedPreferredCredentialResultOutput) CredentialName() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.CredentialName }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagedPreferredCredentialResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether the preferred credential is accessible.
func (o GetManagedPreferredCredentialResultOutput) IsAccessible() pulumi.BoolOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) bool { return v.IsAccessible }).(pulumi.BoolOutput)
}

func (o GetManagedPreferredCredentialResultOutput) ManagedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.ManagedDatabaseId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Vault service secret that contains the database user password.
func (o GetManagedPreferredCredentialResultOutput) PasswordSecretId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.PasswordSecretId }).(pulumi.StringOutput)
}

// The role of the database user.
func (o GetManagedPreferredCredentialResultOutput) Role() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.Role }).(pulumi.StringOutput)
}

// The status of the preferred credential.
func (o GetManagedPreferredCredentialResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.Status }).(pulumi.StringOutput)
}

// The type of preferred credential. Only 'BASIC' is supported currently.
func (o GetManagedPreferredCredentialResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.Type }).(pulumi.StringOutput)
}

// The user name used to connect to the database.
func (o GetManagedPreferredCredentialResultOutput) UserName() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagedPreferredCredentialResult) string { return v.UserName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagedPreferredCredentialResultOutput{})
}