// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package objectstorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func LookupNamespaceMetadata(ctx *pulumi.Context, args *LookupNamespaceMetadataArgs, opts ...pulumi.InvokeOption) (*LookupNamespaceMetadataResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupNamespaceMetadataResult
	err := ctx.Invoke("oci:ObjectStorage/getNamespaceMetadata:getNamespaceMetadata", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNamespaceMetadata.
type LookupNamespaceMetadataArgs struct {
	Namespace string `pulumi:"namespace"`
}

// A collection of values returned by getNamespaceMetadata.
type LookupNamespaceMetadataResult struct {
	DefaultS3compartmentId    string `pulumi:"defaultS3compartmentId"`
	DefaultSwiftCompartmentId string `pulumi:"defaultSwiftCompartmentId"`
	// The provider-assigned unique ID for this managed resource.
	Id        string `pulumi:"id"`
	Namespace string `pulumi:"namespace"`
}

func LookupNamespaceMetadataOutput(ctx *pulumi.Context, args LookupNamespaceMetadataOutputArgs, opts ...pulumi.InvokeOption) LookupNamespaceMetadataResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupNamespaceMetadataResultOutput, error) {
			args := v.(LookupNamespaceMetadataArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ObjectStorage/getNamespaceMetadata:getNamespaceMetadata", args, LookupNamespaceMetadataResultOutput{}, options).(LookupNamespaceMetadataResultOutput), nil
		}).(LookupNamespaceMetadataResultOutput)
}

// A collection of arguments for invoking getNamespaceMetadata.
type LookupNamespaceMetadataOutputArgs struct {
	Namespace pulumi.StringInput `pulumi:"namespace"`
}

func (LookupNamespaceMetadataOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNamespaceMetadataArgs)(nil)).Elem()
}

// A collection of values returned by getNamespaceMetadata.
type LookupNamespaceMetadataResultOutput struct{ *pulumi.OutputState }

func (LookupNamespaceMetadataResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupNamespaceMetadataResult)(nil)).Elem()
}

func (o LookupNamespaceMetadataResultOutput) ToLookupNamespaceMetadataResultOutput() LookupNamespaceMetadataResultOutput {
	return o
}

func (o LookupNamespaceMetadataResultOutput) ToLookupNamespaceMetadataResultOutputWithContext(ctx context.Context) LookupNamespaceMetadataResultOutput {
	return o
}

func (o LookupNamespaceMetadataResultOutput) DefaultS3compartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceMetadataResult) string { return v.DefaultS3compartmentId }).(pulumi.StringOutput)
}

func (o LookupNamespaceMetadataResultOutput) DefaultSwiftCompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceMetadataResult) string { return v.DefaultSwiftCompartmentId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o LookupNamespaceMetadataResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceMetadataResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupNamespaceMetadataResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupNamespaceMetadataResult) string { return v.Namespace }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupNamespaceMetadataResultOutput{})
}
