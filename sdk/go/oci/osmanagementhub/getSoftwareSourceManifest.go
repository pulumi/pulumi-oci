// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Software Source Manifest resource in Oracle Cloud Infrastructure Os Management Hub service.
//
// Returns an archive containing the list of packages in the software source.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/osmanagementhub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := osmanagementhub.GetSoftwareSourceManifest(ctx, &osmanagementhub.GetSoftwareSourceManifestArgs{
//				SoftwareSourceId: testSoftwareSource.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupSoftwareSourceManifest(ctx *pulumi.Context, args *LookupSoftwareSourceManifestArgs, opts ...pulumi.InvokeOption) (*LookupSoftwareSourceManifestResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupSoftwareSourceManifestResult
	err := ctx.Invoke("oci:OsManagementHub/getSoftwareSourceManifest:getSoftwareSourceManifest", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSoftwareSourceManifest.
type LookupSoftwareSourceManifestArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	SoftwareSourceId string `pulumi:"softwareSourceId"`
}

// A collection of values returned by getSoftwareSourceManifest.
type LookupSoftwareSourceManifestResult struct {
	// Provides the manifest content used to update the package list of the software source.
	Content string `pulumi:"content"`
	Id      string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	SoftwareSourceId string `pulumi:"softwareSourceId"`
}

func LookupSoftwareSourceManifestOutput(ctx *pulumi.Context, args LookupSoftwareSourceManifestOutputArgs, opts ...pulumi.InvokeOption) LookupSoftwareSourceManifestResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupSoftwareSourceManifestResultOutput, error) {
			args := v.(LookupSoftwareSourceManifestArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OsManagementHub/getSoftwareSourceManifest:getSoftwareSourceManifest", args, LookupSoftwareSourceManifestResultOutput{}, options).(LookupSoftwareSourceManifestResultOutput), nil
		}).(LookupSoftwareSourceManifestResultOutput)
}

// A collection of arguments for invoking getSoftwareSourceManifest.
type LookupSoftwareSourceManifestOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
	SoftwareSourceId pulumi.StringInput `pulumi:"softwareSourceId"`
}

func (LookupSoftwareSourceManifestOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSoftwareSourceManifestArgs)(nil)).Elem()
}

// A collection of values returned by getSoftwareSourceManifest.
type LookupSoftwareSourceManifestResultOutput struct{ *pulumi.OutputState }

func (LookupSoftwareSourceManifestResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupSoftwareSourceManifestResult)(nil)).Elem()
}

func (o LookupSoftwareSourceManifestResultOutput) ToLookupSoftwareSourceManifestResultOutput() LookupSoftwareSourceManifestResultOutput {
	return o
}

func (o LookupSoftwareSourceManifestResultOutput) ToLookupSoftwareSourceManifestResultOutputWithContext(ctx context.Context) LookupSoftwareSourceManifestResultOutput {
	return o
}

// Provides the manifest content used to update the package list of the software source.
func (o LookupSoftwareSourceManifestResultOutput) Content() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSoftwareSourceManifestResult) string { return v.Content }).(pulumi.StringOutput)
}

func (o LookupSoftwareSourceManifestResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSoftwareSourceManifestResult) string { return v.Id }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
func (o LookupSoftwareSourceManifestResultOutput) SoftwareSourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupSoftwareSourceManifestResult) string { return v.SoftwareSourceId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupSoftwareSourceManifestResultOutput{})
}
