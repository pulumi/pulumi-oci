// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package secrets

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Secretbundle Versions in Oracle Cloud Infrastructure Secrets service.
//
// Lists all secret bundle versions for the specified secret.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Secrets"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Secrets.GetSecretbundleVersions(ctx, &secrets.GetSecretbundleVersionsArgs{
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
func GetSecretbundleVersions(ctx *pulumi.Context, args *GetSecretbundleVersionsArgs, opts ...pulumi.InvokeOption) (*GetSecretbundleVersionsResult, error) {
	var rv GetSecretbundleVersionsResult
	err := ctx.Invoke("oci:Secrets/getSecretbundleVersions:getSecretbundleVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecretbundleVersions.
type GetSecretbundleVersionsArgs struct {
	Filters []GetSecretbundleVersionsFilter `pulumi:"filters"`
	// The OCID of the secret.
	SecretId string `pulumi:"secretId"`
}

// A collection of values returned by getSecretbundleVersions.
type GetSecretbundleVersionsResult struct {
	Filters []GetSecretbundleVersionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of secret_bundle_versions.
	SecretBundleVersions []GetSecretbundleVersionsSecretBundleVersion `pulumi:"secretBundleVersions"`
	// The OCID of the secret.
	SecretId string `pulumi:"secretId"`
}

func GetSecretbundleVersionsOutput(ctx *pulumi.Context, args GetSecretbundleVersionsOutputArgs, opts ...pulumi.InvokeOption) GetSecretbundleVersionsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSecretbundleVersionsResult, error) {
			args := v.(GetSecretbundleVersionsArgs)
			r, err := GetSecretbundleVersions(ctx, &args, opts...)
			var s GetSecretbundleVersionsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSecretbundleVersionsResultOutput)
}

// A collection of arguments for invoking getSecretbundleVersions.
type GetSecretbundleVersionsOutputArgs struct {
	Filters GetSecretbundleVersionsFilterArrayInput `pulumi:"filters"`
	// The OCID of the secret.
	SecretId pulumi.StringInput `pulumi:"secretId"`
}

func (GetSecretbundleVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretbundleVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getSecretbundleVersions.
type GetSecretbundleVersionsResultOutput struct{ *pulumi.OutputState }

func (GetSecretbundleVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecretbundleVersionsResult)(nil)).Elem()
}

func (o GetSecretbundleVersionsResultOutput) ToGetSecretbundleVersionsResultOutput() GetSecretbundleVersionsResultOutput {
	return o
}

func (o GetSecretbundleVersionsResultOutput) ToGetSecretbundleVersionsResultOutputWithContext(ctx context.Context) GetSecretbundleVersionsResultOutput {
	return o
}

func (o GetSecretbundleVersionsResultOutput) Filters() GetSecretbundleVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetSecretbundleVersionsResult) []GetSecretbundleVersionsFilter { return v.Filters }).(GetSecretbundleVersionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecretbundleVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of secret_bundle_versions.
func (o GetSecretbundleVersionsResultOutput) SecretBundleVersions() GetSecretbundleVersionsSecretBundleVersionArrayOutput {
	return o.ApplyT(func(v GetSecretbundleVersionsResult) []GetSecretbundleVersionsSecretBundleVersion {
		return v.SecretBundleVersions
	}).(GetSecretbundleVersionsSecretBundleVersionArrayOutput)
}

// The OCID of the secret.
func (o GetSecretbundleVersionsResultOutput) SecretId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecretbundleVersionsResult) string { return v.SecretId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecretbundleVersionsResultOutput{})
}