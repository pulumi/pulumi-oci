// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Software Source Module Stream resource in Oracle Cloud Infrastructure OS Management service.
//
// Retrieve a detailed description of a module stream from a software source.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OsManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OsManagement.GetSoftwareSourceModuleStream(ctx, &osmanagement.GetSoftwareSourceModuleStreamArgs{
//				ModuleName:       _var.Software_source_module_stream_module_name,
//				SoftwareSourceId: _var.Software_source.Id,
//				StreamName:       _var.Software_source_module_stream_name,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSoftwareSourceModuleStream(ctx *pulumi.Context, args *GetSoftwareSourceModuleStreamArgs, opts ...pulumi.InvokeOption) (*GetSoftwareSourceModuleStreamResult, error) {
	var rv GetSoftwareSourceModuleStreamResult
	err := ctx.Invoke("oci:OsManagement/getSoftwareSourceModuleStream:getSoftwareSourceModuleStream", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSoftwareSourceModuleStream.
type GetSoftwareSourceModuleStreamArgs struct {
	// The name of the module
	ModuleName string `pulumi:"moduleName"`
	// The OCID of the software source.
	SoftwareSourceId string `pulumi:"softwareSourceId"`
	// The name of the stream of the containing module
	StreamName string `pulumi:"streamName"`
}

// A collection of values returned by getSoftwareSourceModuleStream.
type GetSoftwareSourceModuleStreamResult struct {
	// The architecture for which the packages in this module stream were built
	Architecture string `pulumi:"architecture"`
	// A description of the contents of the module stream
	Description string `pulumi:"description"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Indicates if this stream is the default for its module.
	IsDefault bool `pulumi:"isDefault"`
	// The name of the module that contains the stream
	ModuleName string `pulumi:"moduleName"`
	// A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management APIs that interact directly with packages.
	Packages []string `pulumi:"packages"`
	// A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management APIs that interact directly with module stream profiles.  However, it is not URL encoded.
	Profiles []string `pulumi:"profiles"`
	// The OCID of the software source that provides this module stream.
	SoftwareSourceId string `pulumi:"softwareSourceId"`
	// The name of the stream
	StreamName string `pulumi:"streamName"`
}

func GetSoftwareSourceModuleStreamOutput(ctx *pulumi.Context, args GetSoftwareSourceModuleStreamOutputArgs, opts ...pulumi.InvokeOption) GetSoftwareSourceModuleStreamResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSoftwareSourceModuleStreamResult, error) {
			args := v.(GetSoftwareSourceModuleStreamArgs)
			r, err := GetSoftwareSourceModuleStream(ctx, &args, opts...)
			var s GetSoftwareSourceModuleStreamResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSoftwareSourceModuleStreamResultOutput)
}

// A collection of arguments for invoking getSoftwareSourceModuleStream.
type GetSoftwareSourceModuleStreamOutputArgs struct {
	// The name of the module
	ModuleName pulumi.StringInput `pulumi:"moduleName"`
	// The OCID of the software source.
	SoftwareSourceId pulumi.StringInput `pulumi:"softwareSourceId"`
	// The name of the stream of the containing module
	StreamName pulumi.StringInput `pulumi:"streamName"`
}

func (GetSoftwareSourceModuleStreamOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceModuleStreamArgs)(nil)).Elem()
}

// A collection of values returned by getSoftwareSourceModuleStream.
type GetSoftwareSourceModuleStreamResultOutput struct{ *pulumi.OutputState }

func (GetSoftwareSourceModuleStreamResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceModuleStreamResult)(nil)).Elem()
}

func (o GetSoftwareSourceModuleStreamResultOutput) ToGetSoftwareSourceModuleStreamResultOutput() GetSoftwareSourceModuleStreamResultOutput {
	return o
}

func (o GetSoftwareSourceModuleStreamResultOutput) ToGetSoftwareSourceModuleStreamResultOutputWithContext(ctx context.Context) GetSoftwareSourceModuleStreamResultOutput {
	return o
}

// The architecture for which the packages in this module stream were built
func (o GetSoftwareSourceModuleStreamResultOutput) Architecture() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.Architecture }).(pulumi.StringOutput)
}

// A description of the contents of the module stream
func (o GetSoftwareSourceModuleStreamResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.Description }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSoftwareSourceModuleStreamResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates if this stream is the default for its module.
func (o GetSoftwareSourceModuleStreamResultOutput) IsDefault() pulumi.BoolOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) bool { return v.IsDefault }).(pulumi.BoolOutput)
}

// The name of the module that contains the stream
func (o GetSoftwareSourceModuleStreamResultOutput) ModuleName() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.ModuleName }).(pulumi.StringOutput)
}

// A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management APIs that interact directly with packages.
func (o GetSoftwareSourceModuleStreamResultOutput) Packages() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) []string { return v.Packages }).(pulumi.StringArrayOutput)
}

// A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management APIs that interact directly with module stream profiles.  However, it is not URL encoded.
func (o GetSoftwareSourceModuleStreamResultOutput) Profiles() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) []string { return v.Profiles }).(pulumi.StringArrayOutput)
}

// The OCID of the software source that provides this module stream.
func (o GetSoftwareSourceModuleStreamResultOutput) SoftwareSourceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.SoftwareSourceId }).(pulumi.StringOutput)
}

// The name of the stream
func (o GetSoftwareSourceModuleStreamResultOutput) StreamName() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamResult) string { return v.StreamName }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSoftwareSourceModuleStreamResultOutput{})
}