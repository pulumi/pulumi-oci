// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package dataconnectivity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Registry Data Asset resource in Oracle Cloud Infrastructure Data Connectivity service.
//
// Retrieves details of a data asset using the specified identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataConnectivity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DataConnectivity.GetRegistryDataAsset(ctx, &dataconnectivity.GetRegistryDataAssetArgs{
// 			DataAssetKey: _var.Registry_data_asset_data_asset_key,
// 			RegistryId:   oci_data_connectivity_registry.Test_registry.Id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupRegistryDataAsset(ctx *pulumi.Context, args *LookupRegistryDataAssetArgs, opts ...pulumi.InvokeOption) (*LookupRegistryDataAssetResult, error) {
	var rv LookupRegistryDataAssetResult
	err := ctx.Invoke("oci:DataConnectivity/getRegistryDataAsset:getRegistryDataAsset", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRegistryDataAsset.
type LookupRegistryDataAssetArgs struct {
	// The data asset key.
	DataAssetKey string `pulumi:"dataAssetKey"`
	// The registry Ocid.
	RegistryId string `pulumi:"registryId"`
}

// A collection of values returned by getRegistryDataAsset.
type LookupRegistryDataAssetResult struct {
	// Additional properties for the data asset.
	AssetProperties map[string]interface{} `pulumi:"assetProperties"`
	DataAssetKey    string                 `pulumi:"dataAssetKey"`
	// The default connection key.
	DefaultConnections []GetRegistryDataAssetDefaultConnection `pulumi:"defaultConnections"`
	// A user defined description for the object.
	Description string `pulumi:"description"`
	// The external key for the object.
	ExternalKey string `pulumi:"externalKey"`
	Id          string `pulumi:"id"`
	// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
	Identifier string `pulumi:"identifier"`
	// The identifying key for the object.
	Key string `pulumi:"key"`
	// A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadatas []GetRegistryDataAssetMetadata `pulumi:"metadatas"`
	// The property which disciminates the subtypes.
	ModelType string `pulumi:"modelType"`
	// The model version of an object.
	ModelVersion string `pulumi:"modelVersion"`
	// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name string `pulumi:"name"`
	// The type system maps from and to a type.
	NativeTypeSystems []GetRegistryDataAssetNativeTypeSystem `pulumi:"nativeTypeSystems"`
	// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus int `pulumi:"objectStatus"`
	// The version of the object that is used to track changes in the object instance.
	ObjectVersion int `pulumi:"objectVersion"`
	// All the properties for the data asset in a key-value map format.
	Properties map[string]interface{} `pulumi:"properties"`
	RegistryId string                 `pulumi:"registryId"`
	// Information about the object and its parent.
	RegistryMetadatas []GetRegistryDataAssetRegistryMetadata `pulumi:"registryMetadatas"`
	// Specific DataAsset Type
	Type string `pulumi:"type"`
}

func LookupRegistryDataAssetOutput(ctx *pulumi.Context, args LookupRegistryDataAssetOutputArgs, opts ...pulumi.InvokeOption) LookupRegistryDataAssetResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupRegistryDataAssetResult, error) {
			args := v.(LookupRegistryDataAssetArgs)
			r, err := LookupRegistryDataAsset(ctx, &args, opts...)
			var s LookupRegistryDataAssetResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupRegistryDataAssetResultOutput)
}

// A collection of arguments for invoking getRegistryDataAsset.
type LookupRegistryDataAssetOutputArgs struct {
	// The data asset key.
	DataAssetKey pulumi.StringInput `pulumi:"dataAssetKey"`
	// The registry Ocid.
	RegistryId pulumi.StringInput `pulumi:"registryId"`
}

func (LookupRegistryDataAssetOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRegistryDataAssetArgs)(nil)).Elem()
}

// A collection of values returned by getRegistryDataAsset.
type LookupRegistryDataAssetResultOutput struct{ *pulumi.OutputState }

func (LookupRegistryDataAssetResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRegistryDataAssetResult)(nil)).Elem()
}

func (o LookupRegistryDataAssetResultOutput) ToLookupRegistryDataAssetResultOutput() LookupRegistryDataAssetResultOutput {
	return o
}

func (o LookupRegistryDataAssetResultOutput) ToLookupRegistryDataAssetResultOutputWithContext(ctx context.Context) LookupRegistryDataAssetResultOutput {
	return o
}

// Additional properties for the data asset.
func (o LookupRegistryDataAssetResultOutput) AssetProperties() pulumi.MapOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) map[string]interface{} { return v.AssetProperties }).(pulumi.MapOutput)
}

func (o LookupRegistryDataAssetResultOutput) DataAssetKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.DataAssetKey }).(pulumi.StringOutput)
}

// The default connection key.
func (o LookupRegistryDataAssetResultOutput) DefaultConnections() GetRegistryDataAssetDefaultConnectionArrayOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) []GetRegistryDataAssetDefaultConnection {
		return v.DefaultConnections
	}).(GetRegistryDataAssetDefaultConnectionArrayOutput)
}

// A user defined description for the object.
func (o LookupRegistryDataAssetResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Description }).(pulumi.StringOutput)
}

// The external key for the object.
func (o LookupRegistryDataAssetResultOutput) ExternalKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.ExternalKey }).(pulumi.StringOutput)
}

func (o LookupRegistryDataAssetResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Id }).(pulumi.StringOutput)
}

// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
func (o LookupRegistryDataAssetResultOutput) Identifier() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Identifier }).(pulumi.StringOutput)
}

// The identifying key for the object.
func (o LookupRegistryDataAssetResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Key }).(pulumi.StringOutput)
}

// A summary type containing information about the object including its key, name and when/who created/updated it.
func (o LookupRegistryDataAssetResultOutput) Metadatas() GetRegistryDataAssetMetadataArrayOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) []GetRegistryDataAssetMetadata { return v.Metadatas }).(GetRegistryDataAssetMetadataArrayOutput)
}

// The property which disciminates the subtypes.
func (o LookupRegistryDataAssetResultOutput) ModelType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.ModelType }).(pulumi.StringOutput)
}

// The model version of an object.
func (o LookupRegistryDataAssetResultOutput) ModelVersion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.ModelVersion }).(pulumi.StringOutput)
}

// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
func (o LookupRegistryDataAssetResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Name }).(pulumi.StringOutput)
}

// The type system maps from and to a type.
func (o LookupRegistryDataAssetResultOutput) NativeTypeSystems() GetRegistryDataAssetNativeTypeSystemArrayOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) []GetRegistryDataAssetNativeTypeSystem {
		return v.NativeTypeSystems
	}).(GetRegistryDataAssetNativeTypeSystemArrayOutput)
}

// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
func (o LookupRegistryDataAssetResultOutput) ObjectStatus() pulumi.IntOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) int { return v.ObjectStatus }).(pulumi.IntOutput)
}

// The version of the object that is used to track changes in the object instance.
func (o LookupRegistryDataAssetResultOutput) ObjectVersion() pulumi.IntOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) int { return v.ObjectVersion }).(pulumi.IntOutput)
}

// All the properties for the data asset in a key-value map format.
func (o LookupRegistryDataAssetResultOutput) Properties() pulumi.MapOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) map[string]interface{} { return v.Properties }).(pulumi.MapOutput)
}

func (o LookupRegistryDataAssetResultOutput) RegistryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.RegistryId }).(pulumi.StringOutput)
}

// Information about the object and its parent.
func (o LookupRegistryDataAssetResultOutput) RegistryMetadatas() GetRegistryDataAssetRegistryMetadataArrayOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) []GetRegistryDataAssetRegistryMetadata {
		return v.RegistryMetadatas
	}).(GetRegistryDataAssetRegistryMetadataArrayOutput)
}

// Specific DataAsset Type
func (o LookupRegistryDataAssetResultOutput) Type() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRegistryDataAssetResult) string { return v.Type }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupRegistryDataAssetResultOutput{})
}
