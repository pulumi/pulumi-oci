// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bigdataservice

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Bds Instance Get Os Patch in Oracle Cloud Infrastructure Big Data Service service.
//
// # Get the details of an os patch
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/bigdataservice"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := bigdataservice.GetBdsInstanceGetOsPatch(ctx, &bigdataservice.GetBdsInstanceGetOsPatchArgs{
//				BdsInstanceId:  testBdsInstance.Id,
//				OsPatchVersion: bdsInstanceGetOsPatchOsPatchVersion,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetBdsInstanceGetOsPatch(ctx *pulumi.Context, args *GetBdsInstanceGetOsPatchArgs, opts ...pulumi.InvokeOption) (*GetBdsInstanceGetOsPatchResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetBdsInstanceGetOsPatchResult
	err := ctx.Invoke("oci:BigDataService/getBdsInstanceGetOsPatch:getBdsInstanceGetOsPatch", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBdsInstanceGetOsPatch.
type GetBdsInstanceGetOsPatchArgs struct {
	// The OCID of the cluster.
	BdsInstanceId string                           `pulumi:"bdsInstanceId"`
	Filters       []GetBdsInstanceGetOsPatchFilter `pulumi:"filters"`
	// The version of the OS patch.
	OsPatchVersion string `pulumi:"osPatchVersion"`
}

// A collection of values returned by getBdsInstanceGetOsPatch.
type GetBdsInstanceGetOsPatchResult struct {
	BdsInstanceId string                           `pulumi:"bdsInstanceId"`
	Filters       []GetBdsInstanceGetOsPatchFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Minimum BDS version required to install current OS patch.
	MinBdsVersion string `pulumi:"minBdsVersion"`
	// Map of major ODH version to minimum ODH version required to install current OS patch. e.g. {ODH0.9: 0.9.1}
	MinCompatibleOdhVersionMap map[string]string `pulumi:"minCompatibleOdhVersionMap"`
	// Version of the os patch.
	OsPatchVersion string `pulumi:"osPatchVersion"`
	// Type of a specific os patch. REGULAR means standard released os patches. CUSTOM means os patches with some customizations. EMERGENT means os patches with some emergency fixes that should be prioritized.
	PatchType string `pulumi:"patchType"`
	// Released date of the OS patch.
	ReleaseDate string `pulumi:"releaseDate"`
	// List of summaries of individual target packages.
	TargetPackages []GetBdsInstanceGetOsPatchTargetPackage `pulumi:"targetPackages"`
}

func GetBdsInstanceGetOsPatchOutput(ctx *pulumi.Context, args GetBdsInstanceGetOsPatchOutputArgs, opts ...pulumi.InvokeOption) GetBdsInstanceGetOsPatchResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetBdsInstanceGetOsPatchResultOutput, error) {
			args := v.(GetBdsInstanceGetOsPatchArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:BigDataService/getBdsInstanceGetOsPatch:getBdsInstanceGetOsPatch", args, GetBdsInstanceGetOsPatchResultOutput{}, options).(GetBdsInstanceGetOsPatchResultOutput), nil
		}).(GetBdsInstanceGetOsPatchResultOutput)
}

// A collection of arguments for invoking getBdsInstanceGetOsPatch.
type GetBdsInstanceGetOsPatchOutputArgs struct {
	// The OCID of the cluster.
	BdsInstanceId pulumi.StringInput                       `pulumi:"bdsInstanceId"`
	Filters       GetBdsInstanceGetOsPatchFilterArrayInput `pulumi:"filters"`
	// The version of the OS patch.
	OsPatchVersion pulumi.StringInput `pulumi:"osPatchVersion"`
}

func (GetBdsInstanceGetOsPatchOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBdsInstanceGetOsPatchArgs)(nil)).Elem()
}

// A collection of values returned by getBdsInstanceGetOsPatch.
type GetBdsInstanceGetOsPatchResultOutput struct{ *pulumi.OutputState }

func (GetBdsInstanceGetOsPatchResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBdsInstanceGetOsPatchResult)(nil)).Elem()
}

func (o GetBdsInstanceGetOsPatchResultOutput) ToGetBdsInstanceGetOsPatchResultOutput() GetBdsInstanceGetOsPatchResultOutput {
	return o
}

func (o GetBdsInstanceGetOsPatchResultOutput) ToGetBdsInstanceGetOsPatchResultOutputWithContext(ctx context.Context) GetBdsInstanceGetOsPatchResultOutput {
	return o
}

func (o GetBdsInstanceGetOsPatchResultOutput) BdsInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.BdsInstanceId }).(pulumi.StringOutput)
}

func (o GetBdsInstanceGetOsPatchResultOutput) Filters() GetBdsInstanceGetOsPatchFilterArrayOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) []GetBdsInstanceGetOsPatchFilter { return v.Filters }).(GetBdsInstanceGetOsPatchFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetBdsInstanceGetOsPatchResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.Id }).(pulumi.StringOutput)
}

// Minimum BDS version required to install current OS patch.
func (o GetBdsInstanceGetOsPatchResultOutput) MinBdsVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.MinBdsVersion }).(pulumi.StringOutput)
}

// Map of major ODH version to minimum ODH version required to install current OS patch. e.g. {ODH0.9: 0.9.1}
func (o GetBdsInstanceGetOsPatchResultOutput) MinCompatibleOdhVersionMap() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) map[string]string { return v.MinCompatibleOdhVersionMap }).(pulumi.StringMapOutput)
}

// Version of the os patch.
func (o GetBdsInstanceGetOsPatchResultOutput) OsPatchVersion() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.OsPatchVersion }).(pulumi.StringOutput)
}

// Type of a specific os patch. REGULAR means standard released os patches. CUSTOM means os patches with some customizations. EMERGENT means os patches with some emergency fixes that should be prioritized.
func (o GetBdsInstanceGetOsPatchResultOutput) PatchType() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.PatchType }).(pulumi.StringOutput)
}

// Released date of the OS patch.
func (o GetBdsInstanceGetOsPatchResultOutput) ReleaseDate() pulumi.StringOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) string { return v.ReleaseDate }).(pulumi.StringOutput)
}

// List of summaries of individual target packages.
func (o GetBdsInstanceGetOsPatchResultOutput) TargetPackages() GetBdsInstanceGetOsPatchTargetPackageArrayOutput {
	return o.ApplyT(func(v GetBdsInstanceGetOsPatchResult) []GetBdsInstanceGetOsPatchTargetPackage {
		return v.TargetPackages
	}).(GetBdsInstanceGetOsPatchTargetPackageArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetBdsInstanceGetOsPatchResultOutput{})
}
