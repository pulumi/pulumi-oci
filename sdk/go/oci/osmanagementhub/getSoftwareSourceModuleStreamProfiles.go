// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package osmanagementhub

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Software Source Module Stream Profiles in Oracle Cloud Infrastructure Os Management Hub service.
//
// Lists module stream profiles from the specified software source OCID. Filter the list against a variety of
// criteria including but not limited to its module name, stream name, and (profile) name.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/OsManagementHub"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := OsManagementHub.GetSoftwareSourceModuleStreamProfiles(ctx, &osmanagementhub.GetSoftwareSourceModuleStreamProfilesArgs{
//				SoftwareSourceId: oci_os_management_hub_software_source.Test_software_source.Id,
//				ModuleName:       pulumi.StringRef(_var.Software_source_module_stream_profile_module_name),
//				Name:             pulumi.StringRef(_var.Software_source_module_stream_profile_name),
//				StreamName:       pulumi.StringRef(oci_streaming_stream.Test_stream.Name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSoftwareSourceModuleStreamProfiles(ctx *pulumi.Context, args *GetSoftwareSourceModuleStreamProfilesArgs, opts ...pulumi.InvokeOption) (*GetSoftwareSourceModuleStreamProfilesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSoftwareSourceModuleStreamProfilesResult
	err := ctx.Invoke("oci:OsManagementHub/getSoftwareSourceModuleStreamProfiles:getSoftwareSourceModuleStreamProfiles", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSoftwareSourceModuleStreamProfiles.
type GetSoftwareSourceModuleStreamProfilesArgs struct {
	Filters []GetSoftwareSourceModuleStreamProfilesFilter `pulumi:"filters"`
	// The name of a module. This parameter is required if a streamName is specified.
	ModuleName *string `pulumi:"moduleName"`
	// The name of the entity to be queried.
	Name *string `pulumi:"name"`
	// The software source OCID.
	SoftwareSourceId string `pulumi:"softwareSourceId"`
	// The name of the stream of the containing module.  This parameter is required if a profileName is specified.
	StreamName *string `pulumi:"streamName"`
}

// A collection of values returned by getSoftwareSourceModuleStreamProfiles.
type GetSoftwareSourceModuleStreamProfilesResult struct {
	Filters []GetSoftwareSourceModuleStreamProfilesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the module that contains the stream profile.
	ModuleName *string `pulumi:"moduleName"`
	// The list of module_stream_profile_collection.
	ModuleStreamProfileCollections []GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollection `pulumi:"moduleStreamProfileCollections"`
	// The name of the profile.
	Name             *string `pulumi:"name"`
	SoftwareSourceId string  `pulumi:"softwareSourceId"`
	// The name of the stream that contains the profile.
	StreamName *string `pulumi:"streamName"`
}

func GetSoftwareSourceModuleStreamProfilesOutput(ctx *pulumi.Context, args GetSoftwareSourceModuleStreamProfilesOutputArgs, opts ...pulumi.InvokeOption) GetSoftwareSourceModuleStreamProfilesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSoftwareSourceModuleStreamProfilesResult, error) {
			args := v.(GetSoftwareSourceModuleStreamProfilesArgs)
			r, err := GetSoftwareSourceModuleStreamProfiles(ctx, &args, opts...)
			var s GetSoftwareSourceModuleStreamProfilesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSoftwareSourceModuleStreamProfilesResultOutput)
}

// A collection of arguments for invoking getSoftwareSourceModuleStreamProfiles.
type GetSoftwareSourceModuleStreamProfilesOutputArgs struct {
	Filters GetSoftwareSourceModuleStreamProfilesFilterArrayInput `pulumi:"filters"`
	// The name of a module. This parameter is required if a streamName is specified.
	ModuleName pulumi.StringPtrInput `pulumi:"moduleName"`
	// The name of the entity to be queried.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The software source OCID.
	SoftwareSourceId pulumi.StringInput `pulumi:"softwareSourceId"`
	// The name of the stream of the containing module.  This parameter is required if a profileName is specified.
	StreamName pulumi.StringPtrInput `pulumi:"streamName"`
}

func (GetSoftwareSourceModuleStreamProfilesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceModuleStreamProfilesArgs)(nil)).Elem()
}

// A collection of values returned by getSoftwareSourceModuleStreamProfiles.
type GetSoftwareSourceModuleStreamProfilesResultOutput struct{ *pulumi.OutputState }

func (GetSoftwareSourceModuleStreamProfilesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSoftwareSourceModuleStreamProfilesResult)(nil)).Elem()
}

func (o GetSoftwareSourceModuleStreamProfilesResultOutput) ToGetSoftwareSourceModuleStreamProfilesResultOutput() GetSoftwareSourceModuleStreamProfilesResultOutput {
	return o
}

func (o GetSoftwareSourceModuleStreamProfilesResultOutput) ToGetSoftwareSourceModuleStreamProfilesResultOutputWithContext(ctx context.Context) GetSoftwareSourceModuleStreamProfilesResultOutput {
	return o
}

func (o GetSoftwareSourceModuleStreamProfilesResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetSoftwareSourceModuleStreamProfilesResult] {
	return pulumix.Output[GetSoftwareSourceModuleStreamProfilesResult]{
		OutputState: o.OutputState,
	}
}

func (o GetSoftwareSourceModuleStreamProfilesResultOutput) Filters() GetSoftwareSourceModuleStreamProfilesFilterArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) []GetSoftwareSourceModuleStreamProfilesFilter {
		return v.Filters
	}).(GetSoftwareSourceModuleStreamProfilesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSoftwareSourceModuleStreamProfilesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name of the module that contains the stream profile.
func (o GetSoftwareSourceModuleStreamProfilesResultOutput) ModuleName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) *string { return v.ModuleName }).(pulumi.StringPtrOutput)
}

// The list of module_stream_profile_collection.
func (o GetSoftwareSourceModuleStreamProfilesResultOutput) ModuleStreamProfileCollections() GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollectionArrayOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) []GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollection {
		return v.ModuleStreamProfileCollections
	}).(GetSoftwareSourceModuleStreamProfilesModuleStreamProfileCollectionArrayOutput)
}

// The name of the profile.
func (o GetSoftwareSourceModuleStreamProfilesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func (o GetSoftwareSourceModuleStreamProfilesResultOutput) SoftwareSourceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) string { return v.SoftwareSourceId }).(pulumi.StringOutput)
}

// The name of the stream that contains the profile.
func (o GetSoftwareSourceModuleStreamProfilesResultOutput) StreamName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSoftwareSourceModuleStreamProfilesResult) *string { return v.StreamName }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSoftwareSourceModuleStreamProfilesResultOutput{})
}