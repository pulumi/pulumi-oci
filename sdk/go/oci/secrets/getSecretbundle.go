// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package secrets

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Secretbundle resource in Oracle Cloud Infrastructure Secrets service.
//
// Gets a secret bundle that matches either the specified `stage`, `label`, or `versionNumber` parameter.
// If none of these parameters are provided, the bundle for the secret version marked as `CURRENT` will be returned.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/secrets"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := secrets.GetSecretbundle(ctx, &secrets.GetSecretbundleArgs{
//				SecretId:          testSecret.Id,
//				SecretVersionName: pulumi.StringRef(testSecretVersion.Name),
//				Stage:             pulumi.StringRef(secretbundleStage),
//				VersionNumber:     pulumi.StringRef(secretbundleVersionNumber),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecretbundle(ctx *pulumi.Context, args *GetSecretbundleArgs, opts ...pulumi.InvokeOption) (*GetSecretbundleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSecretbundleResult
	err := ctx.Invoke("oci:Secrets/getSecretbundle:getSecretbundle", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecretbundle.
type GetSecretbundleArgs struct {
	// The OCID of the secret.
	SecretId string `pulumi:"secretId"`
	// The name of the secret. (This might be referred to as the name of the secret version. Names are unique across the different versions of a secret.)
	SecretVersionName *string `pulumi:"secretVersionName"`
	// The rotation state of the secret version.
	Stage *string `pulumi:"stage"`
	// The version number of the secret.
	VersionNumber *string `pulumi:"versionNumber"`
}

// A collection of values returned by getSecretbundle.
type GetSecretbundleResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Customer-provided contextual metadata for the secret.
	Metadata map[string]string `pulumi:"metadata"`
	// The contents of the secret.
	SecretBundleContents []GetSecretbundleSecretBundleContent `pulumi:"secretBundleContents"`
	// The OCID of the secret.
	SecretId          string  `pulumi:"secretId"`
	SecretVersionName *string `pulumi:"secretVersionName"`
	Stage             *string `pulumi:"stage"`
	// A list of possible rotation states for the secret version.
	Stages []string `pulumi:"stages"`
	// The time when the secret bundle was created.
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	// An optional property indicating when the secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfExpiry string `pulumi:"timeOfExpiry"`
	// The name of the secret version. Labels are unique across the different versions of a particular secret.
	VersionName string `pulumi:"versionName"`
	// The version number of the secret.
	VersionNumber string `pulumi:"versionNumber"`
}

func GetSecretbundleOutput(ctx *pulumi.Context, args GetSecretbundleOutputArgs, opts ...pulumi.InvokeOption) GetSecretbundleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSecretbundleResultOutput, error) {
			args := v.(GetSecretbundleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Secrets/getSecretbundle:getSecretbundle", args, GetSecretbundleResultOutput{}, options).(GetSecretbundleResultOutput), nil
		}).(GetSecretbundleResultOutput)
}

// A collection of arguments for invoking getSecretbundle.
type GetSecretbundleOutputArgs struct {
	// The OCID of the secret.
	SecretId pulumi.StringInput `pulumi:"secretId"`
	// The name of the secret. (This might be referred to as the name of the secret version. Names are unique across the different versions of a secret.)
	SecretVersionName pulumi.StringPtrInput `pulumi:"secretVersionName"`
	// The rotation state of the secret version.
	Stage pulumi.StringPtrInput `pulumi:"stage"`
	// The version number of the secret.
	VersionNumber pulumi.StringPtrInput `pulumi:"versionNumber"`
}

func (GetSecretbundleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretbundleArgs)(nil)).Elem()
}

// A collection of values returned by getSecretbundle.
type GetSecretbundleResultOutput struct{ *pulumi.OutputState }

func (GetSecretbundleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretbundleResult)(nil)).Elem()
}

func (o GetSecretbundleResultOutput) ToGetSecretbundleResultOutput() GetSecretbundleResultOutput {
	return o
}

func (o GetSecretbundleResultOutput) ToGetSecretbundleResultOutputWithContext(ctx context.Context) GetSecretbundleResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecretbundleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.Id }).(pulumi.StringOutput)
}

// Customer-provided contextual metadata for the secret.
func (o GetSecretbundleResultOutput) Metadata() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetSecretbundleResult) map[string]string { return v.Metadata }).(pulumi.StringMapOutput)
}

// The contents of the secret.
func (o GetSecretbundleResultOutput) SecretBundleContents() GetSecretbundleSecretBundleContentArrayOutput {
	return o.ApplyT(func(v GetSecretbundleResult) []GetSecretbundleSecretBundleContent { return v.SecretBundleContents }).(GetSecretbundleSecretBundleContentArrayOutput)
}

// The OCID of the secret.
func (o GetSecretbundleResultOutput) SecretId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.SecretId }).(pulumi.StringOutput)
}

func (o GetSecretbundleResultOutput) SecretVersionName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecretbundleResult) *string { return v.SecretVersionName }).(pulumi.StringPtrOutput)
}

func (o GetSecretbundleResultOutput) Stage() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecretbundleResult) *string { return v.Stage }).(pulumi.StringPtrOutput)
}

// A list of possible rotation states for the secret version.
func (o GetSecretbundleResultOutput) Stages() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSecretbundleResult) []string { return v.Stages }).(pulumi.StringArrayOutput)
}

// The time when the secret bundle was created.
func (o GetSecretbundleResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// An optional property indicating when to delete the secret version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretbundleResultOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// An optional property indicating when the secret version will expire, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o GetSecretbundleResultOutput) TimeOfExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.TimeOfExpiry }).(pulumi.StringOutput)
}

// The name of the secret version. Labels are unique across the different versions of a particular secret.
func (o GetSecretbundleResultOutput) VersionName() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.VersionName }).(pulumi.StringOutput)
}

// The version number of the secret.
func (o GetSecretbundleResultOutput) VersionNumber() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleResult) string { return v.VersionNumber }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecretbundleResultOutput{})
}
