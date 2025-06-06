// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package vault

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Secrets in Oracle Cloud Infrastructure Vault service.
//
// Lists all secrets in the specified vault and compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/vault"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := vault.GetSecrets(ctx, &vault.GetSecretsArgs{
//				CompartmentId: compartmentId,
//				Name:          pulumi.StringRef(secretName),
//				State:         pulumi.StringRef(secretState),
//				VaultId:       pulumi.StringRef(testVault.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecrets(ctx *pulumi.Context, args *GetSecretsArgs, opts ...pulumi.InvokeOption) (*GetSecretsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSecretsResult
	err := ctx.Invoke("oci:Vault/getSecrets:getSecrets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecrets.
type GetSecretsArgs struct {
	// The OCID of the compartment.
	CompartmentId string             `pulumi:"compartmentId"`
	Filters       []GetSecretsFilter `pulumi:"filters"`
	// The secret name.
	Name *string `pulumi:"name"`
	// A filter that returns only resources that match the specified lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
	// The OCID of the vault.
	VaultId *string `pulumi:"vaultId"`
}

// A collection of values returned by getSecrets.
type GetSecretsResult struct {
	// The OCID of the compartment where you want to create the secret.
	CompartmentId string             `pulumi:"compartmentId"`
	Filters       []GetSecretsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id   string  `pulumi:"id"`
	Name *string `pulumi:"name"`
	// The list of secrets.
	Secrets []GetSecretsSecret `pulumi:"secrets"`
	// The current lifecycle state of the secret.
	State *string `pulumi:"state"`
	// The OCID of the Vault in which the secret exists
	VaultId *string `pulumi:"vaultId"`
}

func GetSecretsOutput(ctx *pulumi.Context, args GetSecretsOutputArgs, opts ...pulumi.InvokeOption) GetSecretsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSecretsResultOutput, error) {
			args := v.(GetSecretsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Vault/getSecrets:getSecrets", args, GetSecretsResultOutput{}, options).(GetSecretsResultOutput), nil
		}).(GetSecretsResultOutput)
}

// A collection of arguments for invoking getSecrets.
type GetSecretsOutputArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput         `pulumi:"compartmentId"`
	Filters       GetSecretsFilterArrayInput `pulumi:"filters"`
	// The secret name.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter that returns only resources that match the specified lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The OCID of the vault.
	VaultId pulumi.StringPtrInput `pulumi:"vaultId"`
}

func (GetSecretsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsArgs)(nil)).Elem()
}

// A collection of values returned by getSecrets.
type GetSecretsResultOutput struct{ *pulumi.OutputState }

func (GetSecretsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretsResult)(nil)).Elem()
}

func (o GetSecretsResultOutput) ToGetSecretsResultOutput() GetSecretsResultOutput {
	return o
}

func (o GetSecretsResultOutput) ToGetSecretsResultOutputWithContext(ctx context.Context) GetSecretsResultOutput {
	return o
}

// The OCID of the compartment where you want to create the secret.
func (o GetSecretsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSecretsResultOutput) Filters() GetSecretsFilterArrayOutput {
	return o.ApplyT(func(v GetSecretsResult) []GetSecretsFilter { return v.Filters }).(GetSecretsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecretsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetSecretsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecretsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The list of secrets.
func (o GetSecretsResultOutput) Secrets() GetSecretsSecretArrayOutput {
	return o.ApplyT(func(v GetSecretsResult) []GetSecretsSecret { return v.Secrets }).(GetSecretsSecretArrayOutput)
}

// The current lifecycle state of the secret.
func (o GetSecretsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecretsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The OCID of the Vault in which the secret exists
func (o GetSecretsResultOutput) VaultId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecretsResult) *string { return v.VaultId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecretsResultOutput{})
}
