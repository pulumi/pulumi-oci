// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Java License resource in Oracle Cloud Infrastructure Jms Java Downloads service.
//
// Return details of the specified Java license type.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/jms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := jms.GetJavaDownloadsJavaLicense(ctx, &jms.GetJavaDownloadsJavaLicenseArgs{
//				LicenseType: javaLicenseLicenseType,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetJavaDownloadsJavaLicense(ctx *pulumi.Context, args *GetJavaDownloadsJavaLicenseArgs, opts ...pulumi.InvokeOption) (*GetJavaDownloadsJavaLicenseResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetJavaDownloadsJavaLicenseResult
	err := ctx.Invoke("oci:Jms/getJavaDownloadsJavaLicense:getJavaDownloadsJavaLicense", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJavaDownloadsJavaLicense.
type GetJavaDownloadsJavaLicenseArgs struct {
	// Unique Java license type.
	LicenseType string `pulumi:"licenseType"`
}

// A collection of values returned by getJavaDownloadsJavaLicense.
type GetJavaDownloadsJavaLicenseResult struct {
	// Commonly used name for the license type.
	DisplayName string `pulumi:"displayName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// License Type
	LicenseType string `pulumi:"licenseType"`
	// Publicly accessible license URL containing the detailed terms and conditions.
	LicenseUrl string `pulumi:"licenseUrl"`
}

func GetJavaDownloadsJavaLicenseOutput(ctx *pulumi.Context, args GetJavaDownloadsJavaLicenseOutputArgs, opts ...pulumi.InvokeOption) GetJavaDownloadsJavaLicenseResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetJavaDownloadsJavaLicenseResultOutput, error) {
			args := v.(GetJavaDownloadsJavaLicenseArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getJavaDownloadsJavaLicense:getJavaDownloadsJavaLicense", args, GetJavaDownloadsJavaLicenseResultOutput{}, options).(GetJavaDownloadsJavaLicenseResultOutput), nil
		}).(GetJavaDownloadsJavaLicenseResultOutput)
}

// A collection of arguments for invoking getJavaDownloadsJavaLicense.
type GetJavaDownloadsJavaLicenseOutputArgs struct {
	// Unique Java license type.
	LicenseType pulumi.StringInput `pulumi:"licenseType"`
}

func (GetJavaDownloadsJavaLicenseOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaLicenseArgs)(nil)).Elem()
}

// A collection of values returned by getJavaDownloadsJavaLicense.
type GetJavaDownloadsJavaLicenseResultOutput struct{ *pulumi.OutputState }

func (GetJavaDownloadsJavaLicenseResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJavaDownloadsJavaLicenseResult)(nil)).Elem()
}

func (o GetJavaDownloadsJavaLicenseResultOutput) ToGetJavaDownloadsJavaLicenseResultOutput() GetJavaDownloadsJavaLicenseResultOutput {
	return o
}

func (o GetJavaDownloadsJavaLicenseResultOutput) ToGetJavaDownloadsJavaLicenseResultOutputWithContext(ctx context.Context) GetJavaDownloadsJavaLicenseResultOutput {
	return o
}

// Commonly used name for the license type.
func (o GetJavaDownloadsJavaLicenseResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaLicenseResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetJavaDownloadsJavaLicenseResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaLicenseResult) string { return v.Id }).(pulumi.StringOutput)
}

// License Type
func (o GetJavaDownloadsJavaLicenseResultOutput) LicenseType() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaLicenseResult) string { return v.LicenseType }).(pulumi.StringOutput)
}

// Publicly accessible license URL containing the detailed terms and conditions.
func (o GetJavaDownloadsJavaLicenseResultOutput) LicenseUrl() pulumi.StringOutput {
	return o.ApplyT(func(v GetJavaDownloadsJavaLicenseResult) string { return v.LicenseUrl }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetJavaDownloadsJavaLicenseResultOutput{})
}
