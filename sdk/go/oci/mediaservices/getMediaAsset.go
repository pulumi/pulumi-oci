// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.
//
// Gets a MediaAsset by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/MediaServices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := MediaServices.GetMediaAsset(ctx, &mediaservices.GetMediaAssetArgs{
//				MediaAssetId: oci_media_services_media_asset.Test_media_asset.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMediaAsset(ctx *pulumi.Context, args *LookupMediaAssetArgs, opts ...pulumi.InvokeOption) (*LookupMediaAssetResult, error) {
	var rv LookupMediaAssetResult
	err := ctx.Invoke("oci:MediaServices/getMediaAsset:getMediaAsset", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMediaAsset.
type LookupMediaAssetArgs struct {
	// Unique MediaAsset identifier
	MediaAssetId string `pulumi:"mediaAssetId"`
}

// A collection of values returned by getMediaAsset.
type LookupMediaAssetResult struct {
	// The name of the object storage bucket where this represented asset is located.
	Bucket string `pulumi:"bucket"`
	// The ID of the compartment containing the MediaAsset.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id string `pulumi:"id"`
	// The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId string `pulumi:"masterMediaAssetId"`
	MediaAssetId       string `pulumi:"mediaAssetId"`
	// List of tags for the MediaAsset.
	MediaAssetTags []GetMediaAssetMediaAssetTag `pulumi:"mediaAssetTags"`
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId string `pulumi:"mediaWorkflowJobId"`
	// JSON string containing the technial metadata for the media asset.
	Metadatas []GetMediaAssetMetadata `pulumi:"metadatas"`
	// The object storage namespace where this asset is located.
	Namespace string `pulumi:"namespace"`
	// The object storage object name that identifies this asset.
	Object string `pulumi:"object"`
	// eTag of the underlying object storage object.
	ObjectEtag string `pulumi:"objectEtag"`
	// The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId string `pulumi:"parentMediaAssetId"`
	// The end index of video segment files.
	SegmentRangeEndIndex string `pulumi:"segmentRangeEndIndex"`
	// The start index for video segment files.
	SegmentRangeStartIndex string `pulumi:"segmentRangeStartIndex"`
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId string `pulumi:"sourceMediaWorkflowId"`
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion string `pulumi:"sourceMediaWorkflowVersion"`
	// The current state of the MediaAsset.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The type of the media asset.
	Type string `pulumi:"type"`
}

func LookupMediaAssetOutput(ctx *pulumi.Context, args LookupMediaAssetOutputArgs, opts ...pulumi.InvokeOption) LookupMediaAssetResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupMediaAssetResult, error) {
			args := v.(LookupMediaAssetArgs)
			r, err := LookupMediaAsset(ctx, &args, opts...)
			var s LookupMediaAssetResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupMediaAssetResultOutput)
}

// A collection of arguments for invoking getMediaAsset.
type LookupMediaAssetOutputArgs struct {
	// Unique MediaAsset identifier
	MediaAssetId pulumi.StringInput `pulumi:"mediaAssetId"`
}

func (LookupMediaAssetOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMediaAssetArgs)(nil)).Elem()
}

// A collection of values returned by getMediaAsset.
type LookupMediaAssetResultOutput struct{ *pulumi.OutputState }

func (LookupMediaAssetResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMediaAssetResult)(nil)).Elem()
}

func (o LookupMediaAssetResultOutput) ToLookupMediaAssetResultOutput() LookupMediaAssetResultOutput {
	return o
}

func (o LookupMediaAssetResultOutput) ToLookupMediaAssetResultOutputWithContext(ctx context.Context) LookupMediaAssetResultOutput {
	return o
}

// The name of the object storage bucket where this represented asset is located.
func (o LookupMediaAssetResultOutput) Bucket() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.Bucket }).(pulumi.StringOutput)
}

// The ID of the compartment containing the MediaAsset.
func (o LookupMediaAssetResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupMediaAssetResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupMediaAssetResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupMediaAssetResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupMediaAssetResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.Id }).(pulumi.StringOutput)
}

// The ID of the senior most asset from which this asset is derived.
func (o LookupMediaAssetResultOutput) MasterMediaAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.MasterMediaAssetId }).(pulumi.StringOutput)
}

func (o LookupMediaAssetResultOutput) MediaAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.MediaAssetId }).(pulumi.StringOutput)
}

// List of tags for the MediaAsset.
func (o LookupMediaAssetResultOutput) MediaAssetTags() GetMediaAssetMediaAssetTagArrayOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) []GetMediaAssetMediaAssetTag { return v.MediaAssetTags }).(GetMediaAssetMediaAssetTagArrayOutput)
}

// The ID of the MediaWorkflowJob used to produce this asset.
func (o LookupMediaAssetResultOutput) MediaWorkflowJobId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.MediaWorkflowJobId }).(pulumi.StringOutput)
}

// JSON string containing the technial metadata for the media asset.
func (o LookupMediaAssetResultOutput) Metadatas() GetMediaAssetMetadataArrayOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) []GetMediaAssetMetadata { return v.Metadatas }).(GetMediaAssetMetadataArrayOutput)
}

// The object storage namespace where this asset is located.
func (o LookupMediaAssetResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// The object storage object name that identifies this asset.
func (o LookupMediaAssetResultOutput) Object() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.Object }).(pulumi.StringOutput)
}

// eTag of the underlying object storage object.
func (o LookupMediaAssetResultOutput) ObjectEtag() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.ObjectEtag }).(pulumi.StringOutput)
}

// The ID of the parent asset from which this asset is derived.
func (o LookupMediaAssetResultOutput) ParentMediaAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.ParentMediaAssetId }).(pulumi.StringOutput)
}

// The end index of video segment files.
func (o LookupMediaAssetResultOutput) SegmentRangeEndIndex() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.SegmentRangeEndIndex }).(pulumi.StringOutput)
}

// The start index for video segment files.
func (o LookupMediaAssetResultOutput) SegmentRangeStartIndex() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.SegmentRangeStartIndex }).(pulumi.StringOutput)
}

// The ID of the MediaWorkflow used to produce this asset.
func (o LookupMediaAssetResultOutput) SourceMediaWorkflowId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.SourceMediaWorkflowId }).(pulumi.StringOutput)
}

// The version of the MediaWorkflow used to produce this asset.
func (o LookupMediaAssetResultOutput) SourceMediaWorkflowVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.SourceMediaWorkflowVersion }).(pulumi.StringOutput)
}

// The current state of the MediaAsset.
func (o LookupMediaAssetResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupMediaAssetResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
func (o LookupMediaAssetResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
func (o LookupMediaAssetResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The type of the media asset.
func (o LookupMediaAssetResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaAssetResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMediaAssetResultOutput{})
}