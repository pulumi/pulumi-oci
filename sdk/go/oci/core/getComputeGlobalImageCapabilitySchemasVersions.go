// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Global Image Capability Schemas Versions in Oracle Cloud Infrastructure Core service.
//
// Lists Compute Global Image Capability Schema versions in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetComputeGlobalImageCapabilitySchemasVersions(ctx, &core.GetComputeGlobalImageCapabilitySchemasVersionsArgs{
//				ComputeGlobalImageCapabilitySchemaId: testComputeGlobalImageCapabilitySchema.Id,
//				DisplayName:                          pulumi.StringRef(computeGlobalImageCapabilitySchemasVersionDisplayName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetComputeGlobalImageCapabilitySchemasVersions(ctx *pulumi.Context, args *GetComputeGlobalImageCapabilitySchemasVersionsArgs, opts ...pulumi.InvokeOption) (*GetComputeGlobalImageCapabilitySchemasVersionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetComputeGlobalImageCapabilitySchemasVersionsResult
	err := ctx.Invoke("oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getComputeGlobalImageCapabilitySchemasVersions.
type GetComputeGlobalImageCapabilitySchemasVersionsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
	ComputeGlobalImageCapabilitySchemaId string `pulumi:"computeGlobalImageCapabilitySchemaId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                                                `pulumi:"displayName"`
	Filters     []GetComputeGlobalImageCapabilitySchemasVersionsFilter `pulumi:"filters"`
}

// A collection of values returned by getComputeGlobalImageCapabilitySchemasVersions.
type GetComputeGlobalImageCapabilitySchemasVersionsResult struct {
	// The ocid of the compute global image capability schema
	ComputeGlobalImageCapabilitySchemaId string `pulumi:"computeGlobalImageCapabilitySchemaId"`
	// The list of compute_global_image_capability_schema_versions.
	ComputeGlobalImageCapabilitySchemaVersions []GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion `pulumi:"computeGlobalImageCapabilitySchemaVersions"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                                                `pulumi:"displayName"`
	Filters     []GetComputeGlobalImageCapabilitySchemasVersionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetComputeGlobalImageCapabilitySchemasVersionsOutput(ctx *pulumi.Context, args GetComputeGlobalImageCapabilitySchemasVersionsOutputArgs, opts ...pulumi.InvokeOption) GetComputeGlobalImageCapabilitySchemasVersionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetComputeGlobalImageCapabilitySchemasVersionsResultOutput, error) {
			args := v.(GetComputeGlobalImageCapabilitySchemasVersionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getComputeGlobalImageCapabilitySchemasVersions:getComputeGlobalImageCapabilitySchemasVersions", args, GetComputeGlobalImageCapabilitySchemasVersionsResultOutput{}, options).(GetComputeGlobalImageCapabilitySchemasVersionsResultOutput), nil
		}).(GetComputeGlobalImageCapabilitySchemasVersionsResultOutput)
}

// A collection of arguments for invoking getComputeGlobalImageCapabilitySchemasVersions.
type GetComputeGlobalImageCapabilitySchemasVersionsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute global image capability schema
	ComputeGlobalImageCapabilitySchemaId pulumi.StringInput `pulumi:"computeGlobalImageCapabilitySchemaId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput                                          `pulumi:"displayName"`
	Filters     GetComputeGlobalImageCapabilitySchemasVersionsFilterArrayInput `pulumi:"filters"`
}

func (GetComputeGlobalImageCapabilitySchemasVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeGlobalImageCapabilitySchemasVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getComputeGlobalImageCapabilitySchemasVersions.
type GetComputeGlobalImageCapabilitySchemasVersionsResultOutput struct{ *pulumi.OutputState }

func (GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeGlobalImageCapabilitySchemasVersionsResult)(nil)).Elem()
}

func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) ToGetComputeGlobalImageCapabilitySchemasVersionsResultOutput() GetComputeGlobalImageCapabilitySchemasVersionsResultOutput {
	return o
}

func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) ToGetComputeGlobalImageCapabilitySchemasVersionsResultOutputWithContext(ctx context.Context) GetComputeGlobalImageCapabilitySchemasVersionsResultOutput {
	return o
}

// The ocid of the compute global image capability schema
func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) ComputeGlobalImageCapabilitySchemaId() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeGlobalImageCapabilitySchemasVersionsResult) string {
		return v.ComputeGlobalImageCapabilitySchemaId
	}).(pulumi.StringOutput)
}

// The list of compute_global_image_capability_schema_versions.
func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) ComputeGlobalImageCapabilitySchemaVersions() GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersionArrayOutput {
	return o.ApplyT(func(v GetComputeGlobalImageCapabilitySchemasVersionsResult) []GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersion {
		return v.ComputeGlobalImageCapabilitySchemaVersions
	}).(GetComputeGlobalImageCapabilitySchemasVersionsComputeGlobalImageCapabilitySchemaVersionArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeGlobalImageCapabilitySchemasVersionsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) Filters() GetComputeGlobalImageCapabilitySchemasVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetComputeGlobalImageCapabilitySchemasVersionsResult) []GetComputeGlobalImageCapabilitySchemasVersionsFilter {
		return v.Filters
	}).(GetComputeGlobalImageCapabilitySchemasVersionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetComputeGlobalImageCapabilitySchemasVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeGlobalImageCapabilitySchemasVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetComputeGlobalImageCapabilitySchemasVersionsResultOutput{})
}
