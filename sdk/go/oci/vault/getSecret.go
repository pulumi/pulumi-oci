// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package vault

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Secret resource in Oracle Cloud Infrastructure Vault service.
//
// Gets information about the specified secret.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Vault"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Vault.GetSecret(ctx, &vault.GetSecretArgs{
//				SecretId: oci_vault_secret.Test_secret.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSecret(ctx *pulumi.Context, args *LookupSecretArgs, opts ...pulumi.InvokeOption) (*LookupSecretResult, error) {
	var rv LookupSecretResult
	err := ctx.Invoke("oci:Vault/getSecret:getSecret", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecret.
type LookupSecretArgs struct {
	// The OCID of the secret.
	SecretId string `pulumi:"secretId"`
}

// A collection of values returned by getSecret.
type LookupSecretResult struct {
	// The OCID of the compartment where you want to create the secret.
	CompartmentId string `pulumi:"compartmentId"`
	// The version number of the secret version that's currently in use.
	CurrentVersionNumber string `pulumi:"currentVersionNumber"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A brief description of the secret. Avoid entering confidential information.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the secret.
	Id string `pulumi:"id"`
	// The OCID of the master encryption key that is used to encrypt the secret.
	KeyId string `pulumi:"keyId"`
	// Additional information about the current lifecycle state of the secret.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Additional metadata that you can use to provide context about how to use the secret or during rotation or other administrative tasks. For example, for a secret that you use to connect to a database, the additional metadata might specify the connection endpoint and the connection string. Provide additional metadata as key-value pairs.
	Metadata       map[string]interface{}   `pulumi:"metadata"`
	SecretContents []GetSecretSecretContent `pulumi:"secretContents"`
	SecretId       string                   `pulumi:"secretId"`
	// The user-friendly name of the secret. Avoid entering confidential information.
	SecretName string `pulumi:"secretName"`
	// A list of rules that control how the secret is used and managed.
	SecretRules []GetSecretSecretRule `pulumi:"secretRules"`
	// The current lifecycle state of the secret.
	State string `pulumi:"state"`
	// A property indicating when the secret was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfCurrentVersionExpiry string `pulumi:"timeOfCurrentVersionExpiry"`
	// An optional property indicating when to delete the secret, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	// The OCID of the Vault in which the secret exists
	VaultId string `pulumi:"vaultId"`
}

func LookupSecretOutput(ctx *pulumi.Context, args LookupSecretOutputArgs, opts ...pulumi.InvokeOption) LookupSecretResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupSecretResult, error) {
			args := v.(LookupSecretArgs)
			r, err := LookupSecret(ctx, &args, opts...)
			var s LookupSecretResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupSecretResultOutput)
}

// A collection of arguments for invoking getSecret.
type LookupSecretOutputArgs struct {
	// The OCID of the secret.
	SecretId pulumi.StringInput `pulumi:"secretId"`
}

func (LookupSecretOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecretArgs)(nil)).Elem()
}

// A collection of values returned by getSecret.
type LookupSecretResultOutput struct{ *pulumi.OutputState }

func (LookupSecretResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSecretResult)(nil)).Elem()
}

func (o LookupSecretResultOutput) ToLookupSecretResultOutput() LookupSecretResultOutput {
	return o
}

func (o LookupSecretResultOutput) ToLookupSecretResultOutputWithContext(ctx context.Context) LookupSecretResultOutput {
	return o
}

// The OCID of the compartment where you want to create the secret.
func (o LookupSecretResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The version number of the secret version that's currently in use.
func (o LookupSecretResultOutput) CurrentVersionNumber() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.CurrentVersionNumber }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupSecretResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSecretResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A brief description of the secret. Avoid entering confidential information.
func (o LookupSecretResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupSecretResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSecretResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the secret.
func (o LookupSecretResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the master encryption key that is used to encrypt the secret.
func (o LookupSecretResultOutput) KeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.KeyId }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state of the secret.
func (o LookupSecretResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Additional metadata that you can use to provide context about how to use the secret or during rotation or other administrative tasks. For example, for a secret that you use to connect to a database, the additional metadata might specify the connection endpoint and the connection string. Provide additional metadata as key-value pairs.
func (o LookupSecretResultOutput) Metadata() pulumi.MapOutput {
	return o.ApplyT(func(v LookupSecretResult) map[string]interface{} { return v.Metadata }).(pulumi.MapOutput)
}

func (o LookupSecretResultOutput) SecretContents() GetSecretSecretContentArrayOutput {
	return o.ApplyT(func(v LookupSecretResult) []GetSecretSecretContent { return v.SecretContents }).(GetSecretSecretContentArrayOutput)
}

func (o LookupSecretResultOutput) SecretId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.SecretId }).(pulumi.StringOutput)
}

// The user-friendly name of the secret. Avoid entering confidential information.
func (o LookupSecretResultOutput) SecretName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.SecretName }).(pulumi.StringOutput)
}

// A list of rules that control how the secret is used and managed.
func (o LookupSecretResultOutput) SecretRules() GetSecretSecretRuleArrayOutput {
	return o.ApplyT(func(v LookupSecretResult) []GetSecretSecretRule { return v.SecretRules }).(GetSecretSecretRuleArrayOutput)
}

// The current lifecycle state of the secret.
func (o LookupSecretResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.State }).(pulumi.StringOutput)
}

// A property indicating when the secret was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupSecretResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// An optional property indicating when the current secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupSecretResultOutput) TimeOfCurrentVersionExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.TimeOfCurrentVersionExpiry }).(pulumi.StringOutput)
}

// An optional property indicating when to delete the secret, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupSecretResultOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// The OCID of the Vault in which the secret exists
func (o LookupSecretResultOutput) VaultId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSecretResult) string { return v.VaultId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSecretResultOutput{})
}