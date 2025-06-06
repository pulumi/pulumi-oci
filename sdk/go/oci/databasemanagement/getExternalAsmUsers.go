// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of External Asm Users in Oracle Cloud Infrastructure Database Management service.
//
// Lists ASM users for the external ASM specified by `externalAsmId`.
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
//			_, err := databasemanagement.GetExternalAsmUsers(ctx, &databasemanagement.GetExternalAsmUsersArgs{
//				ExternalAsmId:        testExternalAsm.Id,
//				OpcNamedCredentialId: pulumi.StringRef(externalAsmUserOpcNamedCredentialId),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetExternalAsmUsers(ctx *pulumi.Context, args *GetExternalAsmUsersArgs, opts ...pulumi.InvokeOption) (*GetExternalAsmUsersResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetExternalAsmUsersResult
	err := ctx.Invoke("oci:DatabaseManagement/getExternalAsmUsers:getExternalAsmUsers", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getExternalAsmUsers.
type GetExternalAsmUsersArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
	ExternalAsmId string                      `pulumi:"externalAsmId"`
	Filters       []GetExternalAsmUsersFilter `pulumi:"filters"`
	// The OCID of the Named Credential.
	OpcNamedCredentialId *string `pulumi:"opcNamedCredentialId"`
}

// A collection of values returned by getExternalAsmUsers.
type GetExternalAsmUsersResult struct {
	ExternalAsmId string `pulumi:"externalAsmId"`
	// The list of external_asm_user_collection.
	ExternalAsmUserCollections []GetExternalAsmUsersExternalAsmUserCollection `pulumi:"externalAsmUserCollections"`
	Filters                    []GetExternalAsmUsersFilter                    `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                   string  `pulumi:"id"`
	OpcNamedCredentialId *string `pulumi:"opcNamedCredentialId"`
}

func GetExternalAsmUsersOutput(ctx *pulumi.Context, args GetExternalAsmUsersOutputArgs, opts ...pulumi.InvokeOption) GetExternalAsmUsersResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetExternalAsmUsersResultOutput, error) {
			args := v.(GetExternalAsmUsersArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseManagement/getExternalAsmUsers:getExternalAsmUsers", args, GetExternalAsmUsersResultOutput{}, options).(GetExternalAsmUsersResultOutput), nil
		}).(GetExternalAsmUsersResultOutput)
}

// A collection of arguments for invoking getExternalAsmUsers.
type GetExternalAsmUsersOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external ASM.
	ExternalAsmId pulumi.StringInput                  `pulumi:"externalAsmId"`
	Filters       GetExternalAsmUsersFilterArrayInput `pulumi:"filters"`
	// The OCID of the Named Credential.
	OpcNamedCredentialId pulumi.StringPtrInput `pulumi:"opcNamedCredentialId"`
}

func (GetExternalAsmUsersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalAsmUsersArgs)(nil)).Elem()
}

// A collection of values returned by getExternalAsmUsers.
type GetExternalAsmUsersResultOutput struct{ *pulumi.OutputState }

func (GetExternalAsmUsersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetExternalAsmUsersResult)(nil)).Elem()
}

func (o GetExternalAsmUsersResultOutput) ToGetExternalAsmUsersResultOutput() GetExternalAsmUsersResultOutput {
	return o
}

func (o GetExternalAsmUsersResultOutput) ToGetExternalAsmUsersResultOutputWithContext(ctx context.Context) GetExternalAsmUsersResultOutput {
	return o
}

func (o GetExternalAsmUsersResultOutput) ExternalAsmId() pulumi.StringOutput {
	return o.ApplyT(func(v GetExternalAsmUsersResult) string { return v.ExternalAsmId }).(pulumi.StringOutput)
}

// The list of external_asm_user_collection.
func (o GetExternalAsmUsersResultOutput) ExternalAsmUserCollections() GetExternalAsmUsersExternalAsmUserCollectionArrayOutput {
	return o.ApplyT(func(v GetExternalAsmUsersResult) []GetExternalAsmUsersExternalAsmUserCollection {
		return v.ExternalAsmUserCollections
	}).(GetExternalAsmUsersExternalAsmUserCollectionArrayOutput)
}

func (o GetExternalAsmUsersResultOutput) Filters() GetExternalAsmUsersFilterArrayOutput {
	return o.ApplyT(func(v GetExternalAsmUsersResult) []GetExternalAsmUsersFilter { return v.Filters }).(GetExternalAsmUsersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetExternalAsmUsersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetExternalAsmUsersResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetExternalAsmUsersResultOutput) OpcNamedCredentialId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetExternalAsmUsersResult) *string { return v.OpcNamedCredentialId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetExternalAsmUsersResultOutput{})
}
