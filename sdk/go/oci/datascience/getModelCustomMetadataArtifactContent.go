// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datascience

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Model Custom Metadata Artifact Content resource in Oracle Cloud Infrastructure Data Science service.
//
// Downloads model custom metadata artifact content for specified model metadata key.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datascience"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datascience.GetModelCustomMetadataArtifactContent(ctx, &datascience.GetModelCustomMetadataArtifactContentArgs{
//				MetadatumKeyName: testKey.Name,
//				ModelId:          testModel.Id,
//				Range:            pulumi.StringRef(modelCustomMetadataArtifactContentRange),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetModelCustomMetadataArtifactContent(ctx *pulumi.Context, args *GetModelCustomMetadataArtifactContentArgs, opts ...pulumi.InvokeOption) (*GetModelCustomMetadataArtifactContentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetModelCustomMetadataArtifactContentResult
	err := ctx.Invoke("oci:DataScience/getModelCustomMetadataArtifactContent:getModelCustomMetadataArtifactContent", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getModelCustomMetadataArtifactContent.
type GetModelCustomMetadataArtifactContentArgs struct {
	// The name of the model metadatum in the metadata.
	MetadatumKeyName string `pulumi:"metadatumKeyName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId string `pulumi:"modelId"`
	// Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
	Range *string `pulumi:"range"`
}

// A collection of values returned by getModelCustomMetadataArtifactContent.
type GetModelCustomMetadataArtifactContentResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id               string  `pulumi:"id"`
	MetadatumKeyName string  `pulumi:"metadatumKeyName"`
	ModelId          string  `pulumi:"modelId"`
	Range            *string `pulumi:"range"`
}

func GetModelCustomMetadataArtifactContentOutput(ctx *pulumi.Context, args GetModelCustomMetadataArtifactContentOutputArgs, opts ...pulumi.InvokeOption) GetModelCustomMetadataArtifactContentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetModelCustomMetadataArtifactContentResultOutput, error) {
			args := v.(GetModelCustomMetadataArtifactContentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataScience/getModelCustomMetadataArtifactContent:getModelCustomMetadataArtifactContent", args, GetModelCustomMetadataArtifactContentResultOutput{}, options).(GetModelCustomMetadataArtifactContentResultOutput), nil
		}).(GetModelCustomMetadataArtifactContentResultOutput)
}

// A collection of arguments for invoking getModelCustomMetadataArtifactContent.
type GetModelCustomMetadataArtifactContentOutputArgs struct {
	// The name of the model metadatum in the metadata.
	MetadatumKeyName pulumi.StringInput `pulumi:"metadatumKeyName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
	ModelId pulumi.StringInput `pulumi:"modelId"`
	// Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
	Range pulumi.StringPtrInput `pulumi:"range"`
}

func (GetModelCustomMetadataArtifactContentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetModelCustomMetadataArtifactContentArgs)(nil)).Elem()
}

// A collection of values returned by getModelCustomMetadataArtifactContent.
type GetModelCustomMetadataArtifactContentResultOutput struct{ *pulumi.OutputState }

func (GetModelCustomMetadataArtifactContentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetModelCustomMetadataArtifactContentResult)(nil)).Elem()
}

func (o GetModelCustomMetadataArtifactContentResultOutput) ToGetModelCustomMetadataArtifactContentResultOutput() GetModelCustomMetadataArtifactContentResultOutput {
	return o
}

func (o GetModelCustomMetadataArtifactContentResultOutput) ToGetModelCustomMetadataArtifactContentResultOutputWithContext(ctx context.Context) GetModelCustomMetadataArtifactContentResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetModelCustomMetadataArtifactContentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetModelCustomMetadataArtifactContentResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetModelCustomMetadataArtifactContentResultOutput) MetadatumKeyName() pulumi.StringOutput {
	return o.ApplyT(func(v GetModelCustomMetadataArtifactContentResult) string { return v.MetadatumKeyName }).(pulumi.StringOutput)
}

func (o GetModelCustomMetadataArtifactContentResultOutput) ModelId() pulumi.StringOutput {
	return o.ApplyT(func(v GetModelCustomMetadataArtifactContentResult) string { return v.ModelId }).(pulumi.StringOutput)
}

func (o GetModelCustomMetadataArtifactContentResultOutput) Range() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetModelCustomMetadataArtifactContentResult) *string { return v.Range }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetModelCustomMetadataArtifactContentResultOutput{})
}
