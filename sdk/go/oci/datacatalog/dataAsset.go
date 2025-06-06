// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datacatalog

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Data Asset resource in Oracle Cloud Infrastructure Data Catalog service.
//
// Create a new data asset.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datacatalog"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datacatalog.NewDataAsset(ctx, "test_data_asset", &datacatalog.DataAssetArgs{
//				CatalogId:   pulumi.Any(testCatalog.Id),
//				DisplayName: pulumi.Any(dataAssetDisplayName),
//				TypeKey:     pulumi.Any(dataAssetTypeKey),
//				Description: pulumi.Any(dataAssetDescription),
//				Properties:  pulumi.Any(dataAssetProperties),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// DataAssets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataCatalog/dataAsset:DataAsset test_data_asset "catalogs/{catalogId}/dataAssets/{dataAssetKey}"
// ```
type DataAsset struct {
	pulumi.CustomResourceState

	// Unique catalog identifier.
	CatalogId pulumi.StringOutput `pulumi:"catalogId"`
	// OCID of the user who created the data asset.
	CreatedById pulumi.StringOutput `pulumi:"createdById"`
	// (Updatable) Detailed description of the data asset.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// External URI that can be used to reference the object. Format will differ based on the type of object.
	ExternalKey pulumi.StringOutput `pulumi:"externalKey"`
	// Unique data asset key that is immutable.
	Key pulumi.StringOutput `pulumi:"key"`
	// A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
	LifecycleDetails pulumi.StringOutput    `pulumi:"lifecycleDetails"`
	Properties       pulumi.StringMapOutput `pulumi:"properties"`
	// The current state of the data asset.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeHarvested pulumi.StringOutput `pulumi:"timeHarvested"`
	// The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The key of the data asset type. This can be obtained via the '/types' endpoint.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TypeKey pulumi.StringOutput `pulumi:"typeKey"`
	// OCID of the user who last modified the data asset.
	UpdatedById pulumi.StringOutput `pulumi:"updatedById"`
	// URI to the data asset instance in the API.
	Uri pulumi.StringOutput `pulumi:"uri"`
}

// NewDataAsset registers a new resource with the given unique name, arguments, and options.
func NewDataAsset(ctx *pulumi.Context,
	name string, args *DataAssetArgs, opts ...pulumi.ResourceOption) (*DataAsset, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CatalogId == nil {
		return nil, errors.New("invalid value for required argument 'CatalogId'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.TypeKey == nil {
		return nil, errors.New("invalid value for required argument 'TypeKey'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DataAsset
	err := ctx.RegisterResource("oci:DataCatalog/dataAsset:DataAsset", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDataAsset gets an existing DataAsset resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDataAsset(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DataAssetState, opts ...pulumi.ResourceOption) (*DataAsset, error) {
	var resource DataAsset
	err := ctx.ReadResource("oci:DataCatalog/dataAsset:DataAsset", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DataAsset resources.
type dataAssetState struct {
	// Unique catalog identifier.
	CatalogId *string `pulumi:"catalogId"`
	// OCID of the user who created the data asset.
	CreatedById *string `pulumi:"createdById"`
	// (Updatable) Detailed description of the data asset.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// External URI that can be used to reference the object. Format will differ based on the type of object.
	ExternalKey *string `pulumi:"externalKey"`
	// Unique data asset key that is immutable.
	Key *string `pulumi:"key"`
	// A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
	LifecycleDetails *string           `pulumi:"lifecycleDetails"`
	Properties       map[string]string `pulumi:"properties"`
	// The current state of the data asset.
	State *string `pulumi:"state"`
	// The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeHarvested *string `pulumi:"timeHarvested"`
	// The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The key of the data asset type. This can be obtained via the '/types' endpoint.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TypeKey *string `pulumi:"typeKey"`
	// OCID of the user who last modified the data asset.
	UpdatedById *string `pulumi:"updatedById"`
	// URI to the data asset instance in the API.
	Uri *string `pulumi:"uri"`
}

type DataAssetState struct {
	// Unique catalog identifier.
	CatalogId pulumi.StringPtrInput
	// OCID of the user who created the data asset.
	CreatedById pulumi.StringPtrInput
	// (Updatable) Detailed description of the data asset.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// External URI that can be used to reference the object. Format will differ based on the type of object.
	ExternalKey pulumi.StringPtrInput
	// Unique data asset key that is immutable.
	Key pulumi.StringPtrInput
	// A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
	LifecycleDetails pulumi.StringPtrInput
	Properties       pulumi.StringMapInput
	// The current state of the data asset.
	State pulumi.StringPtrInput
	// The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeHarvested pulumi.StringPtrInput
	// The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
	// The key of the data asset type. This can be obtained via the '/types' endpoint.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TypeKey pulumi.StringPtrInput
	// OCID of the user who last modified the data asset.
	UpdatedById pulumi.StringPtrInput
	// URI to the data asset instance in the API.
	Uri pulumi.StringPtrInput
}

func (DataAssetState) ElementType() reflect.Type {
	return reflect.TypeOf((*dataAssetState)(nil)).Elem()
}

type dataAssetArgs struct {
	// Unique catalog identifier.
	CatalogId string `pulumi:"catalogId"`
	// (Updatable) Detailed description of the data asset.
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string            `pulumi:"displayName"`
	Properties  map[string]string `pulumi:"properties"`
	// The key of the data asset type. This can be obtained via the '/types' endpoint.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TypeKey string `pulumi:"typeKey"`
}

// The set of arguments for constructing a DataAsset resource.
type DataAssetArgs struct {
	// Unique catalog identifier.
	CatalogId pulumi.StringInput
	// (Updatable) Detailed description of the data asset.
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringInput
	Properties  pulumi.StringMapInput
	// The key of the data asset type. This can be obtained via the '/types' endpoint.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TypeKey pulumi.StringInput
}

func (DataAssetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dataAssetArgs)(nil)).Elem()
}

type DataAssetInput interface {
	pulumi.Input

	ToDataAssetOutput() DataAssetOutput
	ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput
}

func (*DataAsset) ElementType() reflect.Type {
	return reflect.TypeOf((**DataAsset)(nil)).Elem()
}

func (i *DataAsset) ToDataAssetOutput() DataAssetOutput {
	return i.ToDataAssetOutputWithContext(context.Background())
}

func (i *DataAsset) ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetOutput)
}

// DataAssetArrayInput is an input type that accepts DataAssetArray and DataAssetArrayOutput values.
// You can construct a concrete instance of `DataAssetArrayInput` via:
//
//	DataAssetArray{ DataAssetArgs{...} }
type DataAssetArrayInput interface {
	pulumi.Input

	ToDataAssetArrayOutput() DataAssetArrayOutput
	ToDataAssetArrayOutputWithContext(context.Context) DataAssetArrayOutput
}

type DataAssetArray []DataAssetInput

func (DataAssetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataAsset)(nil)).Elem()
}

func (i DataAssetArray) ToDataAssetArrayOutput() DataAssetArrayOutput {
	return i.ToDataAssetArrayOutputWithContext(context.Background())
}

func (i DataAssetArray) ToDataAssetArrayOutputWithContext(ctx context.Context) DataAssetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetArrayOutput)
}

// DataAssetMapInput is an input type that accepts DataAssetMap and DataAssetMapOutput values.
// You can construct a concrete instance of `DataAssetMapInput` via:
//
//	DataAssetMap{ "key": DataAssetArgs{...} }
type DataAssetMapInput interface {
	pulumi.Input

	ToDataAssetMapOutput() DataAssetMapOutput
	ToDataAssetMapOutputWithContext(context.Context) DataAssetMapOutput
}

type DataAssetMap map[string]DataAssetInput

func (DataAssetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataAsset)(nil)).Elem()
}

func (i DataAssetMap) ToDataAssetMapOutput() DataAssetMapOutput {
	return i.ToDataAssetMapOutputWithContext(context.Background())
}

func (i DataAssetMap) ToDataAssetMapOutputWithContext(ctx context.Context) DataAssetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetMapOutput)
}

type DataAssetOutput struct{ *pulumi.OutputState }

func (DataAssetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DataAsset)(nil)).Elem()
}

func (o DataAssetOutput) ToDataAssetOutput() DataAssetOutput {
	return o
}

func (o DataAssetOutput) ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput {
	return o
}

// Unique catalog identifier.
func (o DataAssetOutput) CatalogId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.CatalogId }).(pulumi.StringOutput)
}

// OCID of the user who created the data asset.
func (o DataAssetOutput) CreatedById() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.CreatedById }).(pulumi.StringOutput)
}

// (Updatable) Detailed description of the data asset.
func (o DataAssetOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly display name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o DataAssetOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// External URI that can be used to reference the object. Format will differ based on the type of object.
func (o DataAssetOutput) ExternalKey() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.ExternalKey }).(pulumi.StringOutput)
}

// Unique data asset key that is immutable.
func (o DataAssetOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.Key }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. An object not in ACTIVE state may have functional limitations, see service documentation for details.
func (o DataAssetOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o DataAssetOutput) Properties() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringMapOutput { return v.Properties }).(pulumi.StringMapOutput)
}

// The current state of the data asset.
func (o DataAssetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the data asset was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339). Example: `2019-03-25T21:10:29.600Z`
func (o DataAssetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The last time that a harvest was performed on the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o DataAssetOutput) TimeHarvested() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TimeHarvested }).(pulumi.StringOutput)
}

// The last time that any change was made to the data asset. An [RFC3339](https://tools.ietf.org/html/rfc3339) formatted datetime string.
func (o DataAssetOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The key of the data asset type. This can be obtained via the '/types' endpoint.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DataAssetOutput) TypeKey() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TypeKey }).(pulumi.StringOutput)
}

// OCID of the user who last modified the data asset.
func (o DataAssetOutput) UpdatedById() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.UpdatedById }).(pulumi.StringOutput)
}

// URI to the data asset instance in the API.
func (o DataAssetOutput) Uri() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.Uri }).(pulumi.StringOutput)
}

type DataAssetArrayOutput struct{ *pulumi.OutputState }

func (DataAssetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataAsset)(nil)).Elem()
}

func (o DataAssetArrayOutput) ToDataAssetArrayOutput() DataAssetArrayOutput {
	return o
}

func (o DataAssetArrayOutput) ToDataAssetArrayOutputWithContext(ctx context.Context) DataAssetArrayOutput {
	return o
}

func (o DataAssetArrayOutput) Index(i pulumi.IntInput) DataAssetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DataAsset {
		return vs[0].([]*DataAsset)[vs[1].(int)]
	}).(DataAssetOutput)
}

type DataAssetMapOutput struct{ *pulumi.OutputState }

func (DataAssetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataAsset)(nil)).Elem()
}

func (o DataAssetMapOutput) ToDataAssetMapOutput() DataAssetMapOutput {
	return o
}

func (o DataAssetMapOutput) ToDataAssetMapOutputWithContext(ctx context.Context) DataAssetMapOutput {
	return o
}

func (o DataAssetMapOutput) MapIndex(k pulumi.StringInput) DataAssetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DataAsset {
		return vs[0].(map[string]*DataAsset)[vs[1].(string)]
	}).(DataAssetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetInput)(nil)).Elem(), &DataAsset{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetArrayInput)(nil)).Elem(), DataAssetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetMapInput)(nil)).Elem(), DataAssetMap{})
	pulumi.RegisterOutputType(DataAssetOutput{})
	pulumi.RegisterOutputType(DataAssetArrayOutput{})
	pulumi.RegisterOutputType(DataAssetMapOutput{})
}
