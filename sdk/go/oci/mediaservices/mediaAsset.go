// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Media Asset resource in Oracle Cloud Infrastructure Media Services service.
//
// Creates a new MediaAsset.
//
// ## Import
//
// MediaAssets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:MediaServices/mediaAsset:MediaAsset test_media_asset "id"
// ```
type MediaAsset struct {
	pulumi.CustomResourceState

	// The name of the object storage bucket where this asset is located.
	Bucket pulumi.StringOutput `pulumi:"bucket"`
	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapOutput `pulumi:"freeformTags"`
	IsLockOverride pulumi.BoolOutput      `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks MediaAssetLockArrayOutput `pulumi:"locks"`
	// (Updatable) The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId pulumi.StringOutput `pulumi:"masterMediaAssetId"`
	// (Updatable) list of tags for the MediaAsset.
	MediaAssetTags MediaAssetMediaAssetTagArrayOutput `pulumi:"mediaAssetTags"`
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId pulumi.StringOutput `pulumi:"mediaWorkflowJobId"`
	// (Updatable) List of Metadata.
	Metadatas MediaAssetMetadataArrayOutput `pulumi:"metadatas"`
	// The object storage namespace where this asset is located.
	Namespace pulumi.StringOutput `pulumi:"namespace"`
	// The object storage object name that identifies this asset.
	Object pulumi.StringOutput `pulumi:"object"`
	// eTag of the underlying object storage object.
	ObjectEtag pulumi.StringOutput `pulumi:"objectEtag"`
	// (Updatable) The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId pulumi.StringOutput `pulumi:"parentMediaAssetId"`
	// The end index for video segment files.
	SegmentRangeEndIndex pulumi.StringOutput `pulumi:"segmentRangeEndIndex"`
	// The start index for video segment files.
	SegmentRangeStartIndex pulumi.StringOutput `pulumi:"segmentRangeStartIndex"`
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId pulumi.StringOutput `pulumi:"sourceMediaWorkflowId"`
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion pulumi.StringOutput `pulumi:"sourceMediaWorkflowVersion"`
	// The current state of the MediaAsset.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// (Updatable) The type of the media asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Type pulumi.StringOutput `pulumi:"type"`
}

// NewMediaAsset registers a new resource with the given unique name, arguments, and options.
func NewMediaAsset(ctx *pulumi.Context,
	name string, args *MediaAssetArgs, opts ...pulumi.ResourceOption) (*MediaAsset, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.Type == nil {
		return nil, errors.New("invalid value for required argument 'Type'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource MediaAsset
	err := ctx.RegisterResource("oci:MediaServices/mediaAsset:MediaAsset", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetMediaAsset gets an existing MediaAsset resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetMediaAsset(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *MediaAssetState, opts ...pulumi.ResourceOption) (*MediaAsset, error) {
	var resource MediaAsset
	err := ctx.ReadResource("oci:MediaServices/mediaAsset:MediaAsset", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering MediaAsset resources.
type mediaAssetState struct {
	// The name of the object storage bucket where this asset is located.
	Bucket *string `pulumi:"bucket"`
	// (Updatable) Compartment Identifier.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks []MediaAssetLock `pulumi:"locks"`
	// (Updatable) The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId *string `pulumi:"masterMediaAssetId"`
	// (Updatable) list of tags for the MediaAsset.
	MediaAssetTags []MediaAssetMediaAssetTag `pulumi:"mediaAssetTags"`
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId *string `pulumi:"mediaWorkflowJobId"`
	// (Updatable) List of Metadata.
	Metadatas []MediaAssetMetadata `pulumi:"metadatas"`
	// The object storage namespace where this asset is located.
	Namespace *string `pulumi:"namespace"`
	// The object storage object name that identifies this asset.
	Object *string `pulumi:"object"`
	// eTag of the underlying object storage object.
	ObjectEtag *string `pulumi:"objectEtag"`
	// (Updatable) The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId *string `pulumi:"parentMediaAssetId"`
	// The end index for video segment files.
	SegmentRangeEndIndex *string `pulumi:"segmentRangeEndIndex"`
	// The start index for video segment files.
	SegmentRangeStartIndex *string `pulumi:"segmentRangeStartIndex"`
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId *string `pulumi:"sourceMediaWorkflowId"`
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion *string `pulumi:"sourceMediaWorkflowVersion"`
	// The current state of the MediaAsset.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// (Updatable) The type of the media asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Type *string `pulumi:"type"`
}

type MediaAssetState struct {
	// The name of the object storage bucket where this asset is located.
	Bucket pulumi.StringPtrInput
	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// Locks associated with this resource.
	Locks MediaAssetLockArrayInput
	// (Updatable) The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId pulumi.StringPtrInput
	// (Updatable) list of tags for the MediaAsset.
	MediaAssetTags MediaAssetMediaAssetTagArrayInput
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId pulumi.StringPtrInput
	// (Updatable) List of Metadata.
	Metadatas MediaAssetMetadataArrayInput
	// The object storage namespace where this asset is located.
	Namespace pulumi.StringPtrInput
	// The object storage object name that identifies this asset.
	Object pulumi.StringPtrInput
	// eTag of the underlying object storage object.
	ObjectEtag pulumi.StringPtrInput
	// (Updatable) The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId pulumi.StringPtrInput
	// The end index for video segment files.
	SegmentRangeEndIndex pulumi.StringPtrInput
	// The start index for video segment files.
	SegmentRangeStartIndex pulumi.StringPtrInput
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId pulumi.StringPtrInput
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion pulumi.StringPtrInput
	// The current state of the MediaAsset.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// (Updatable) The type of the media asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Type pulumi.StringPtrInput
}

func (MediaAssetState) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaAssetState)(nil)).Elem()
}

type mediaAssetArgs struct {
	// The name of the object storage bucket where this asset is located.
	Bucket *string `pulumi:"bucket"`
	// (Updatable) Compartment Identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   map[string]string `pulumi:"freeformTags"`
	IsLockOverride *bool             `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks []MediaAssetLock `pulumi:"locks"`
	// (Updatable) The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId *string `pulumi:"masterMediaAssetId"`
	// (Updatable) list of tags for the MediaAsset.
	MediaAssetTags []MediaAssetMediaAssetTag `pulumi:"mediaAssetTags"`
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId *string `pulumi:"mediaWorkflowJobId"`
	// (Updatable) List of Metadata.
	Metadatas []MediaAssetMetadata `pulumi:"metadatas"`
	// The object storage namespace where this asset is located.
	Namespace *string `pulumi:"namespace"`
	// The object storage object name that identifies this asset.
	Object *string `pulumi:"object"`
	// eTag of the underlying object storage object.
	ObjectEtag *string `pulumi:"objectEtag"`
	// (Updatable) The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId *string `pulumi:"parentMediaAssetId"`
	// The end index for video segment files.
	SegmentRangeEndIndex *string `pulumi:"segmentRangeEndIndex"`
	// The start index for video segment files.
	SegmentRangeStartIndex *string `pulumi:"segmentRangeStartIndex"`
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId *string `pulumi:"sourceMediaWorkflowId"`
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion *string `pulumi:"sourceMediaWorkflowVersion"`
	// (Updatable) The type of the media asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Type string `pulumi:"type"`
}

// The set of arguments for constructing a MediaAsset resource.
type MediaAssetArgs struct {
	// The name of the object storage bucket where this asset is located.
	Bucket pulumi.StringPtrInput
	// (Updatable) Compartment Identifier.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags   pulumi.StringMapInput
	IsLockOverride pulumi.BoolPtrInput
	// Locks associated with this resource.
	Locks MediaAssetLockArrayInput
	// (Updatable) The ID of the senior most asset from which this asset is derived.
	MasterMediaAssetId pulumi.StringPtrInput
	// (Updatable) list of tags for the MediaAsset.
	MediaAssetTags MediaAssetMediaAssetTagArrayInput
	// The ID of the MediaWorkflowJob used to produce this asset.
	MediaWorkflowJobId pulumi.StringPtrInput
	// (Updatable) List of Metadata.
	Metadatas MediaAssetMetadataArrayInput
	// The object storage namespace where this asset is located.
	Namespace pulumi.StringPtrInput
	// The object storage object name that identifies this asset.
	Object pulumi.StringPtrInput
	// eTag of the underlying object storage object.
	ObjectEtag pulumi.StringPtrInput
	// (Updatable) The ID of the parent asset from which this asset is derived.
	ParentMediaAssetId pulumi.StringPtrInput
	// The end index for video segment files.
	SegmentRangeEndIndex pulumi.StringPtrInput
	// The start index for video segment files.
	SegmentRangeStartIndex pulumi.StringPtrInput
	// The ID of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowId pulumi.StringPtrInput
	// The version of the MediaWorkflow used to produce this asset.
	SourceMediaWorkflowVersion pulumi.StringPtrInput
	// (Updatable) The type of the media asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Type pulumi.StringInput
}

func (MediaAssetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*mediaAssetArgs)(nil)).Elem()
}

type MediaAssetInput interface {
	pulumi.Input

	ToMediaAssetOutput() MediaAssetOutput
	ToMediaAssetOutputWithContext(ctx context.Context) MediaAssetOutput
}

func (*MediaAsset) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaAsset)(nil)).Elem()
}

func (i *MediaAsset) ToMediaAssetOutput() MediaAssetOutput {
	return i.ToMediaAssetOutputWithContext(context.Background())
}

func (i *MediaAsset) ToMediaAssetOutputWithContext(ctx context.Context) MediaAssetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaAssetOutput)
}

// MediaAssetArrayInput is an input type that accepts MediaAssetArray and MediaAssetArrayOutput values.
// You can construct a concrete instance of `MediaAssetArrayInput` via:
//
//	MediaAssetArray{ MediaAssetArgs{...} }
type MediaAssetArrayInput interface {
	pulumi.Input

	ToMediaAssetArrayOutput() MediaAssetArrayOutput
	ToMediaAssetArrayOutputWithContext(context.Context) MediaAssetArrayOutput
}

type MediaAssetArray []MediaAssetInput

func (MediaAssetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaAsset)(nil)).Elem()
}

func (i MediaAssetArray) ToMediaAssetArrayOutput() MediaAssetArrayOutput {
	return i.ToMediaAssetArrayOutputWithContext(context.Background())
}

func (i MediaAssetArray) ToMediaAssetArrayOutputWithContext(ctx context.Context) MediaAssetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaAssetArrayOutput)
}

// MediaAssetMapInput is an input type that accepts MediaAssetMap and MediaAssetMapOutput values.
// You can construct a concrete instance of `MediaAssetMapInput` via:
//
//	MediaAssetMap{ "key": MediaAssetArgs{...} }
type MediaAssetMapInput interface {
	pulumi.Input

	ToMediaAssetMapOutput() MediaAssetMapOutput
	ToMediaAssetMapOutputWithContext(context.Context) MediaAssetMapOutput
}

type MediaAssetMap map[string]MediaAssetInput

func (MediaAssetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaAsset)(nil)).Elem()
}

func (i MediaAssetMap) ToMediaAssetMapOutput() MediaAssetMapOutput {
	return i.ToMediaAssetMapOutputWithContext(context.Background())
}

func (i MediaAssetMap) ToMediaAssetMapOutputWithContext(ctx context.Context) MediaAssetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(MediaAssetMapOutput)
}

type MediaAssetOutput struct{ *pulumi.OutputState }

func (MediaAssetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**MediaAsset)(nil)).Elem()
}

func (o MediaAssetOutput) ToMediaAssetOutput() MediaAssetOutput {
	return o
}

func (o MediaAssetOutput) ToMediaAssetOutputWithContext(ctx context.Context) MediaAssetOutput {
	return o
}

// The name of the object storage bucket where this asset is located.
func (o MediaAssetOutput) Bucket() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.Bucket }).(pulumi.StringOutput)
}

// (Updatable) Compartment Identifier.
func (o MediaAssetOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o MediaAssetOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Display name for the Media Asset. Does not have to be unique. Avoid entering confidential information.
func (o MediaAssetOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o MediaAssetOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

func (o MediaAssetOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.BoolOutput { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// Locks associated with this resource.
func (o MediaAssetOutput) Locks() MediaAssetLockArrayOutput {
	return o.ApplyT(func(v *MediaAsset) MediaAssetLockArrayOutput { return v.Locks }).(MediaAssetLockArrayOutput)
}

// (Updatable) The ID of the senior most asset from which this asset is derived.
func (o MediaAssetOutput) MasterMediaAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.MasterMediaAssetId }).(pulumi.StringOutput)
}

// (Updatable) list of tags for the MediaAsset.
func (o MediaAssetOutput) MediaAssetTags() MediaAssetMediaAssetTagArrayOutput {
	return o.ApplyT(func(v *MediaAsset) MediaAssetMediaAssetTagArrayOutput { return v.MediaAssetTags }).(MediaAssetMediaAssetTagArrayOutput)
}

// The ID of the MediaWorkflowJob used to produce this asset.
func (o MediaAssetOutput) MediaWorkflowJobId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.MediaWorkflowJobId }).(pulumi.StringOutput)
}

// (Updatable) List of Metadata.
func (o MediaAssetOutput) Metadatas() MediaAssetMetadataArrayOutput {
	return o.ApplyT(func(v *MediaAsset) MediaAssetMetadataArrayOutput { return v.Metadatas }).(MediaAssetMetadataArrayOutput)
}

// The object storage namespace where this asset is located.
func (o MediaAssetOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.Namespace }).(pulumi.StringOutput)
}

// The object storage object name that identifies this asset.
func (o MediaAssetOutput) Object() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.Object }).(pulumi.StringOutput)
}

// eTag of the underlying object storage object.
func (o MediaAssetOutput) ObjectEtag() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.ObjectEtag }).(pulumi.StringOutput)
}

// (Updatable) The ID of the parent asset from which this asset is derived.
func (o MediaAssetOutput) ParentMediaAssetId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.ParentMediaAssetId }).(pulumi.StringOutput)
}

// The end index for video segment files.
func (o MediaAssetOutput) SegmentRangeEndIndex() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.SegmentRangeEndIndex }).(pulumi.StringOutput)
}

// The start index for video segment files.
func (o MediaAssetOutput) SegmentRangeStartIndex() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.SegmentRangeStartIndex }).(pulumi.StringOutput)
}

// The ID of the MediaWorkflow used to produce this asset.
func (o MediaAssetOutput) SourceMediaWorkflowId() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.SourceMediaWorkflowId }).(pulumi.StringOutput)
}

// The version of the MediaWorkflow used to produce this asset.
func (o MediaAssetOutput) SourceMediaWorkflowVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.SourceMediaWorkflowVersion }).(pulumi.StringOutput)
}

// The current state of the MediaAsset.
func (o MediaAssetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o MediaAssetOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when the MediaAsset was created. An RFC3339 formatted datetime string.
func (o MediaAssetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
func (o MediaAssetOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// (Updatable) The type of the media asset.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o MediaAssetOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v *MediaAsset) pulumi.StringOutput { return v.Type }).(pulumi.StringOutput)
}

type MediaAssetArrayOutput struct{ *pulumi.OutputState }

func (MediaAssetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*MediaAsset)(nil)).Elem()
}

func (o MediaAssetArrayOutput) ToMediaAssetArrayOutput() MediaAssetArrayOutput {
	return o
}

func (o MediaAssetArrayOutput) ToMediaAssetArrayOutputWithContext(ctx context.Context) MediaAssetArrayOutput {
	return o
}

func (o MediaAssetArrayOutput) Index(i pulumi.IntInput) MediaAssetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *MediaAsset {
		return vs[0].([]*MediaAsset)[vs[1].(int)]
	}).(MediaAssetOutput)
}

type MediaAssetMapOutput struct{ *pulumi.OutputState }

func (MediaAssetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*MediaAsset)(nil)).Elem()
}

func (o MediaAssetMapOutput) ToMediaAssetMapOutput() MediaAssetMapOutput {
	return o
}

func (o MediaAssetMapOutput) ToMediaAssetMapOutputWithContext(ctx context.Context) MediaAssetMapOutput {
	return o
}

func (o MediaAssetMapOutput) MapIndex(k pulumi.StringInput) MediaAssetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *MediaAsset {
		return vs[0].(map[string]*MediaAsset)[vs[1].(string)]
	}).(MediaAssetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*MediaAssetInput)(nil)).Elem(), &MediaAsset{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaAssetArrayInput)(nil)).Elem(), MediaAssetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*MediaAssetMapInput)(nil)).Elem(), MediaAssetMap{})
	pulumi.RegisterOutputType(MediaAssetOutput{})
	pulumi.RegisterOutputType(MediaAssetArrayOutput{})
	pulumi.RegisterOutputType(MediaAssetMapOutput{})
}
