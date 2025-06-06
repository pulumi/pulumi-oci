// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compute Image Capability Schemas in Oracle Cloud Infrastructure Core service.
//
// Lists Compute Image Capability Schema in the specified compartment. You can also query by a specific imageId.
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
//			_, err := core.GetComputeImageCapabilitySchemas(ctx, &core.GetComputeImageCapabilitySchemasArgs{
//				CompartmentId: pulumi.StringRef(compartmentId),
//				DisplayName:   pulumi.StringRef(computeImageCapabilitySchemaDisplayName),
//				ImageId:       pulumi.StringRef(testImage.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetComputeImageCapabilitySchemas(ctx *pulumi.Context, args *GetComputeImageCapabilitySchemasArgs, opts ...pulumi.InvokeOption) (*GetComputeImageCapabilitySchemasResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetComputeImageCapabilitySchemasResult
	err := ctx.Invoke("oci:Core/getComputeImageCapabilitySchemas:getComputeImageCapabilitySchemas", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getComputeImageCapabilitySchemas.
type GetComputeImageCapabilitySchemasArgs struct {
	// A filter to return only resources that match the given compartment OCID exactly.
	CompartmentId *string `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName *string                                  `pulumi:"displayName"`
	Filters     []GetComputeImageCapabilitySchemasFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
	ImageId *string `pulumi:"imageId"`
}

// A collection of values returned by getComputeImageCapabilitySchemas.
type GetComputeImageCapabilitySchemasResult struct {
	// The OCID of the compartment containing the compute global image capability schema
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of compute_image_capability_schemas.
	ComputeImageCapabilitySchemas []GetComputeImageCapabilitySchemasComputeImageCapabilitySchema `pulumi:"computeImageCapabilitySchemas"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                                  `pulumi:"displayName"`
	Filters     []GetComputeImageCapabilitySchemasFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the image associated with this compute image capability schema
	ImageId *string `pulumi:"imageId"`
}

func GetComputeImageCapabilitySchemasOutput(ctx *pulumi.Context, args GetComputeImageCapabilitySchemasOutputArgs, opts ...pulumi.InvokeOption) GetComputeImageCapabilitySchemasResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetComputeImageCapabilitySchemasResultOutput, error) {
			args := v.(GetComputeImageCapabilitySchemasArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getComputeImageCapabilitySchemas:getComputeImageCapabilitySchemas", args, GetComputeImageCapabilitySchemasResultOutput{}, options).(GetComputeImageCapabilitySchemasResultOutput), nil
		}).(GetComputeImageCapabilitySchemasResultOutput)
}

// A collection of arguments for invoking getComputeImageCapabilitySchemas.
type GetComputeImageCapabilitySchemasOutputArgs struct {
	// A filter to return only resources that match the given compartment OCID exactly.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the given display name exactly.
	DisplayName pulumi.StringPtrInput                            `pulumi:"displayName"`
	Filters     GetComputeImageCapabilitySchemasFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of an image.
	ImageId pulumi.StringPtrInput `pulumi:"imageId"`
}

func (GetComputeImageCapabilitySchemasOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeImageCapabilitySchemasArgs)(nil)).Elem()
}

// A collection of values returned by getComputeImageCapabilitySchemas.
type GetComputeImageCapabilitySchemasResultOutput struct{ *pulumi.OutputState }

func (GetComputeImageCapabilitySchemasResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetComputeImageCapabilitySchemasResult)(nil)).Elem()
}

func (o GetComputeImageCapabilitySchemasResultOutput) ToGetComputeImageCapabilitySchemasResultOutput() GetComputeImageCapabilitySchemasResultOutput {
	return o
}

func (o GetComputeImageCapabilitySchemasResultOutput) ToGetComputeImageCapabilitySchemasResultOutputWithContext(ctx context.Context) GetComputeImageCapabilitySchemasResultOutput {
	return o
}

// The OCID of the compartment containing the compute global image capability schema
func (o GetComputeImageCapabilitySchemasResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The list of compute_image_capability_schemas.
func (o GetComputeImageCapabilitySchemasResultOutput) ComputeImageCapabilitySchemas() GetComputeImageCapabilitySchemasComputeImageCapabilitySchemaArrayOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) []GetComputeImageCapabilitySchemasComputeImageCapabilitySchema {
		return v.ComputeImageCapabilitySchemas
	}).(GetComputeImageCapabilitySchemasComputeImageCapabilitySchemaArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetComputeImageCapabilitySchemasResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetComputeImageCapabilitySchemasResultOutput) Filters() GetComputeImageCapabilitySchemasFilterArrayOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) []GetComputeImageCapabilitySchemasFilter {
		return v.Filters
	}).(GetComputeImageCapabilitySchemasFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetComputeImageCapabilitySchemasResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the image associated with this compute image capability schema
func (o GetComputeImageCapabilitySchemasResultOutput) ImageId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetComputeImageCapabilitySchemasResult) *string { return v.ImageId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetComputeImageCapabilitySchemasResultOutput{})
}
