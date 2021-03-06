// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package dataconnectivity

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Registry Connection resource in Oracle Cloud Infrastructure Data Connectivity service.
//
// Creates a connection under an existing data asset.
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
// 		_, err := DataConnectivity.NewRegistryConnection(ctx, "testRegistryConnection", &DataConnectivity.RegistryConnectionArgs{
// 			Identifier: pulumi.Any(_var.Registry_connection_identifier),
// 			Properties: pulumi.Any(_var.Registry_connection_properties),
// 			RegistryId: pulumi.Any(oci_data_connectivity_registry.Test_registry.Id),
// 			Type:       pulumi.Any(_var.Registry_connection_type),
// 			ConnectionProperties: dataconnectivity.RegistryConnectionConnectionPropertyArray{
// 				&dataconnectivity.RegistryConnectionConnectionPropertyArgs{
// 					Name:  pulumi.Any(_var.Registry_connection_connection_properties_name),
// 					Value: pulumi.Any(_var.Registry_connection_connection_properties_value),
// 				},
// 			},
// 			Description: pulumi.Any(_var.Registry_connection_description),
// 			IsDefault:   pulumi.Any(_var.Registry_connection_is_default),
// 			Key:         pulumi.Any(_var.Registry_connection_key),
// 			Metadata: &dataconnectivity.RegistryConnectionMetadataArgs{
// 				Aggregator: &dataconnectivity.RegistryConnectionMetadataAggregatorArgs{
// 					Description: pulumi.Any(_var.Registry_connection_metadata_aggregator_description),
// 					Identifier:  pulumi.Any(_var.Registry_connection_metadata_aggregator_identifier),
// 					Key:         pulumi.Any(_var.Registry_connection_metadata_aggregator_key),
// 					Name:        pulumi.Any(_var.Registry_connection_metadata_aggregator_name),
// 					Type:        pulumi.Any(_var.Registry_connection_metadata_aggregator_type),
// 				},
// 				AggregatorKey:   pulumi.Any(_var.Registry_connection_metadata_aggregator_key),
// 				CreatedBy:       pulumi.Any(_var.Registry_connection_metadata_created_by),
// 				CreatedByName:   pulumi.Any(_var.Registry_connection_metadata_created_by_name),
// 				IdentifierPath:  pulumi.Any(_var.Registry_connection_metadata_identifier_path),
// 				InfoFields:      pulumi.Any(_var.Registry_connection_metadata_info_fields),
// 				IsFavorite:      pulumi.Any(_var.Registry_connection_metadata_is_favorite),
// 				Labels:          pulumi.Any(_var.Registry_connection_metadata_labels),
// 				RegistryVersion: pulumi.Any(_var.Registry_connection_metadata_registry_version),
// 				TimeCreated:     pulumi.Any(_var.Registry_connection_metadata_time_created),
// 				TimeUpdated:     pulumi.Any(_var.Registry_connection_metadata_time_updated),
// 				UpdatedBy:       pulumi.Any(_var.Registry_connection_metadata_updated_by),
// 				UpdatedByName:   pulumi.Any(_var.Registry_connection_metadata_updated_by_name),
// 			},
// 			ModelType:     pulumi.Any(_var.Registry_connection_model_type),
// 			ModelVersion:  pulumi.Any(_var.Registry_connection_model_version),
// 			ObjectStatus:  pulumi.Any(_var.Registry_connection_object_status),
// 			ObjectVersion: pulumi.Any(_var.Registry_connection_object_version),
// 			PrimarySchema: &dataconnectivity.RegistryConnectionPrimarySchemaArgs{
// 				Identifier:        pulumi.Any(_var.Registry_connection_primary_schema_identifier),
// 				Key:               pulumi.Any(_var.Registry_connection_primary_schema_key),
// 				ModelType:         pulumi.Any(_var.Registry_connection_primary_schema_model_type),
// 				Name:              pulumi.Any(_var.Registry_connection_primary_schema_name),
// 				DefaultConnection: pulumi.Any(_var.Registry_connection_primary_schema_default_connection),
// 				Description:       pulumi.Any(_var.Registry_connection_primary_schema_description),
// 				ExternalKey:       pulumi.Any(_var.Registry_connection_primary_schema_external_key),
// 				IsHasContainers:   pulumi.Any(_var.Registry_connection_primary_schema_is_has_containers),
// 				Metadata: &dataconnectivity.RegistryConnectionPrimarySchemaMetadataArgs{
// 					Aggregator: &dataconnectivity.RegistryConnectionPrimarySchemaMetadataAggregatorArgs{
// 						Description: pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_description),
// 						Identifier:  pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_identifier),
// 						Key:         pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_key),
// 						Name:        pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_name),
// 						Type:        pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_type),
// 					},
// 					AggregatorKey:   pulumi.Any(_var.Registry_connection_primary_schema_metadata_aggregator_key),
// 					CreatedBy:       pulumi.Any(_var.Registry_connection_primary_schema_metadata_created_by),
// 					CreatedByName:   pulumi.Any(_var.Registry_connection_primary_schema_metadata_created_by_name),
// 					IdentifierPath:  pulumi.Any(_var.Registry_connection_primary_schema_metadata_identifier_path),
// 					InfoFields:      pulumi.Any(_var.Registry_connection_primary_schema_metadata_info_fields),
// 					IsFavorite:      pulumi.Any(_var.Registry_connection_primary_schema_metadata_is_favorite),
// 					Labels:          pulumi.Any(_var.Registry_connection_primary_schema_metadata_labels),
// 					RegistryVersion: pulumi.Any(_var.Registry_connection_primary_schema_metadata_registry_version),
// 					TimeCreated:     pulumi.Any(_var.Registry_connection_primary_schema_metadata_time_created),
// 					TimeUpdated:     pulumi.Any(_var.Registry_connection_primary_schema_metadata_time_updated),
// 					UpdatedBy:       pulumi.Any(_var.Registry_connection_primary_schema_metadata_updated_by),
// 					UpdatedByName:   pulumi.Any(_var.Registry_connection_primary_schema_metadata_updated_by_name),
// 				},
// 				ModelVersion:  pulumi.Any(_var.Registry_connection_primary_schema_model_version),
// 				ObjectStatus:  pulumi.Any(_var.Registry_connection_primary_schema_object_status),
// 				ObjectVersion: pulumi.Any(_var.Registry_connection_primary_schema_object_version),
// 				ParentRef: &dataconnectivity.RegistryConnectionPrimarySchemaParentRefArgs{
// 					Parent: pulumi.Any(_var.Registry_connection_primary_schema_parent_ref_parent),
// 				},
// 				ResourceName: pulumi.Any(_var.Registry_connection_primary_schema_resource_name),
// 			},
// 			RegistryMetadata: &dataconnectivity.RegistryConnectionRegistryMetadataArgs{
// 				AggregatorKey:     pulumi.Any(_var.Registry_connection_registry_metadata_aggregator_key),
// 				CreatedByUserId:   pulumi.Any(oci_identity_user.Test_user.Id),
// 				CreatedByUserName: pulumi.Any(oci_identity_user.Test_user.Name),
// 				IsFavorite:        pulumi.Any(_var.Registry_connection_registry_metadata_is_favorite),
// 				Key:               pulumi.Any(_var.Registry_connection_registry_metadata_key),
// 				Labels:            pulumi.Any(_var.Registry_connection_registry_metadata_labels),
// 				RegistryVersion:   pulumi.Any(_var.Registry_connection_registry_metadata_registry_version),
// 				TimeCreated:       pulumi.Any(_var.Registry_connection_registry_metadata_time_created),
// 				TimeUpdated:       pulumi.Any(_var.Registry_connection_registry_metadata_time_updated),
// 				UpdatedByUserId:   pulumi.Any(oci_identity_user.Test_user.Id),
// 				UpdatedByUserName: pulumi.Any(oci_identity_user.Test_user.Name),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// RegistryConnections can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:DataConnectivity/registryConnection:RegistryConnection test_registry_connection "registries/{registryId}/connections/{connectionKey}"
// ```
type RegistryConnection struct {
	pulumi.CustomResourceState

	// (Updatable) The properties for the connection.
	ConnectionProperties RegistryConnectionConnectionPropertyArrayOutput `pulumi:"connectionProperties"`
	// (Updatable) The description of the aggregator.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The identifier of the aggregator.
	Identifier pulumi.StringOutput `pulumi:"identifier"`
	// (Updatable) The default property for the connection.
	IsDefault pulumi.BoolOutput `pulumi:"isDefault"`
	// (Updatable) The identifying key for the object.
	Key pulumi.StringOutput `pulumi:"key"`
	// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadata RegistryConnectionMetadataOutput `pulumi:"metadata"`
	// (Updatable) The object's type.
	ModelType pulumi.StringOutput `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringOutput `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntOutput `pulumi:"objectStatus"`
	// (Updatable) The version of the object that is used to track changes in the object instance.
	ObjectVersion pulumi.IntOutput `pulumi:"objectVersion"`
	// (Updatable) The schema object.
	PrimarySchema RegistryConnectionPrimarySchemaOutput `pulumi:"primarySchema"`
	// (Updatable) All the properties for the connection in a key-value map format.
	Properties pulumi.MapOutput `pulumi:"properties"`
	// The registry Ocid.
	RegistryId pulumi.StringOutput `pulumi:"registryId"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata RegistryConnectionRegistryMetadataOutput `pulumi:"registryMetadata"`
	// (Updatable) Specific Connection Type
	Type pulumi.StringOutput `pulumi:"type"`
}

// NewRegistryConnection registers a new resource with the given unique name, arguments, and options.
func NewRegistryConnection(ctx *pulumi.Context,
	name string, args *RegistryConnectionArgs, opts ...pulumi.ResourceOption) (*RegistryConnection, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Identifier == nil {
		return nil, errors.New("invalid value for required argument 'Identifier'")
	}
	if args.Properties == nil {
		return nil, errors.New("invalid value for required argument 'Properties'")
	}
	if args.RegistryId == nil {
		return nil, errors.New("invalid value for required argument 'RegistryId'")
	}
	if args.Type == nil {
		return nil, errors.New("invalid value for required argument 'Type'")
	}
	var resource RegistryConnection
	err := ctx.RegisterResource("oci:DataConnectivity/registryConnection:RegistryConnection", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetRegistryConnection gets an existing RegistryConnection resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetRegistryConnection(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *RegistryConnectionState, opts ...pulumi.ResourceOption) (*RegistryConnection, error) {
	var resource RegistryConnection
	err := ctx.ReadResource("oci:DataConnectivity/registryConnection:RegistryConnection", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering RegistryConnection resources.
type registryConnectionState struct {
	// (Updatable) The properties for the connection.
	ConnectionProperties []RegistryConnectionConnectionProperty `pulumi:"connectionProperties"`
	// (Updatable) The description of the aggregator.
	Description *string `pulumi:"description"`
	// (Updatable) The identifier of the aggregator.
	Identifier *string `pulumi:"identifier"`
	// (Updatable) The default property for the connection.
	IsDefault *bool `pulumi:"isDefault"`
	// (Updatable) The identifying key for the object.
	Key *string `pulumi:"key"`
	// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadata *RegistryConnectionMetadata `pulumi:"metadata"`
	// (Updatable) The object's type.
	ModelType *string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// (Updatable) The version of the object that is used to track changes in the object instance.
	ObjectVersion *int `pulumi:"objectVersion"`
	// (Updatable) The schema object.
	PrimarySchema *RegistryConnectionPrimarySchema `pulumi:"primarySchema"`
	// (Updatable) All the properties for the connection in a key-value map format.
	Properties map[string]interface{} `pulumi:"properties"`
	// The registry Ocid.
	RegistryId *string `pulumi:"registryId"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata *RegistryConnectionRegistryMetadata `pulumi:"registryMetadata"`
	// (Updatable) Specific Connection Type
	Type *string `pulumi:"type"`
}

type RegistryConnectionState struct {
	// (Updatable) The properties for the connection.
	ConnectionProperties RegistryConnectionConnectionPropertyArrayInput
	// (Updatable) The description of the aggregator.
	Description pulumi.StringPtrInput
	// (Updatable) The identifier of the aggregator.
	Identifier pulumi.StringPtrInput
	// (Updatable) The default property for the connection.
	IsDefault pulumi.BoolPtrInput
	// (Updatable) The identifying key for the object.
	Key pulumi.StringPtrInput
	// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadata RegistryConnectionMetadataPtrInput
	// (Updatable) The object's type.
	ModelType pulumi.StringPtrInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// (Updatable) The version of the object that is used to track changes in the object instance.
	ObjectVersion pulumi.IntPtrInput
	// (Updatable) The schema object.
	PrimarySchema RegistryConnectionPrimarySchemaPtrInput
	// (Updatable) All the properties for the connection in a key-value map format.
	Properties pulumi.MapInput
	// The registry Ocid.
	RegistryId pulumi.StringPtrInput
	// (Updatable) Information about the object and its parent.
	RegistryMetadata RegistryConnectionRegistryMetadataPtrInput
	// (Updatable) Specific Connection Type
	Type pulumi.StringPtrInput
}

func (RegistryConnectionState) ElementType() reflect.Type {
	return reflect.TypeOf((*registryConnectionState)(nil)).Elem()
}

type registryConnectionArgs struct {
	// (Updatable) The properties for the connection.
	ConnectionProperties []RegistryConnectionConnectionProperty `pulumi:"connectionProperties"`
	// (Updatable) The description of the aggregator.
	Description *string `pulumi:"description"`
	// (Updatable) The identifier of the aggregator.
	Identifier string `pulumi:"identifier"`
	// (Updatable) The default property for the connection.
	IsDefault *bool `pulumi:"isDefault"`
	// (Updatable) The identifying key for the object.
	Key *string `pulumi:"key"`
	// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadata *RegistryConnectionMetadata `pulumi:"metadata"`
	// (Updatable) The object's type.
	ModelType *string `pulumi:"modelType"`
	// (Updatable) The object's model version.
	ModelVersion *string `pulumi:"modelVersion"`
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name *string `pulumi:"name"`
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus *int `pulumi:"objectStatus"`
	// (Updatable) The version of the object that is used to track changes in the object instance.
	ObjectVersion *int `pulumi:"objectVersion"`
	// (Updatable) The schema object.
	PrimarySchema *RegistryConnectionPrimarySchema `pulumi:"primarySchema"`
	// (Updatable) All the properties for the connection in a key-value map format.
	Properties map[string]interface{} `pulumi:"properties"`
	// The registry Ocid.
	RegistryId string `pulumi:"registryId"`
	// (Updatable) Information about the object and its parent.
	RegistryMetadata *RegistryConnectionRegistryMetadata `pulumi:"registryMetadata"`
	// (Updatable) Specific Connection Type
	Type string `pulumi:"type"`
}

// The set of arguments for constructing a RegistryConnection resource.
type RegistryConnectionArgs struct {
	// (Updatable) The properties for the connection.
	ConnectionProperties RegistryConnectionConnectionPropertyArrayInput
	// (Updatable) The description of the aggregator.
	Description pulumi.StringPtrInput
	// (Updatable) The identifier of the aggregator.
	Identifier pulumi.StringInput
	// (Updatable) The default property for the connection.
	IsDefault pulumi.BoolPtrInput
	// (Updatable) The identifying key for the object.
	Key pulumi.StringPtrInput
	// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
	Metadata RegistryConnectionMetadataPtrInput
	// (Updatable) The object's type.
	ModelType pulumi.StringPtrInput
	// (Updatable) The object's model version.
	ModelVersion pulumi.StringPtrInput
	// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
	Name pulumi.StringPtrInput
	// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
	ObjectStatus pulumi.IntPtrInput
	// (Updatable) The version of the object that is used to track changes in the object instance.
	ObjectVersion pulumi.IntPtrInput
	// (Updatable) The schema object.
	PrimarySchema RegistryConnectionPrimarySchemaPtrInput
	// (Updatable) All the properties for the connection in a key-value map format.
	Properties pulumi.MapInput
	// The registry Ocid.
	RegistryId pulumi.StringInput
	// (Updatable) Information about the object and its parent.
	RegistryMetadata RegistryConnectionRegistryMetadataPtrInput
	// (Updatable) Specific Connection Type
	Type pulumi.StringInput
}

func (RegistryConnectionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*registryConnectionArgs)(nil)).Elem()
}

type RegistryConnectionInput interface {
	pulumi.Input

	ToRegistryConnectionOutput() RegistryConnectionOutput
	ToRegistryConnectionOutputWithContext(ctx context.Context) RegistryConnectionOutput
}

func (*RegistryConnection) ElementType() reflect.Type {
	return reflect.TypeOf((**RegistryConnection)(nil)).Elem()
}

func (i *RegistryConnection) ToRegistryConnectionOutput() RegistryConnectionOutput {
	return i.ToRegistryConnectionOutputWithContext(context.Background())
}

func (i *RegistryConnection) ToRegistryConnectionOutputWithContext(ctx context.Context) RegistryConnectionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RegistryConnectionOutput)
}

// RegistryConnectionArrayInput is an input type that accepts RegistryConnectionArray and RegistryConnectionArrayOutput values.
// You can construct a concrete instance of `RegistryConnectionArrayInput` via:
//
//          RegistryConnectionArray{ RegistryConnectionArgs{...} }
type RegistryConnectionArrayInput interface {
	pulumi.Input

	ToRegistryConnectionArrayOutput() RegistryConnectionArrayOutput
	ToRegistryConnectionArrayOutputWithContext(context.Context) RegistryConnectionArrayOutput
}

type RegistryConnectionArray []RegistryConnectionInput

func (RegistryConnectionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RegistryConnection)(nil)).Elem()
}

func (i RegistryConnectionArray) ToRegistryConnectionArrayOutput() RegistryConnectionArrayOutput {
	return i.ToRegistryConnectionArrayOutputWithContext(context.Background())
}

func (i RegistryConnectionArray) ToRegistryConnectionArrayOutputWithContext(ctx context.Context) RegistryConnectionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RegistryConnectionArrayOutput)
}

// RegistryConnectionMapInput is an input type that accepts RegistryConnectionMap and RegistryConnectionMapOutput values.
// You can construct a concrete instance of `RegistryConnectionMapInput` via:
//
//          RegistryConnectionMap{ "key": RegistryConnectionArgs{...} }
type RegistryConnectionMapInput interface {
	pulumi.Input

	ToRegistryConnectionMapOutput() RegistryConnectionMapOutput
	ToRegistryConnectionMapOutputWithContext(context.Context) RegistryConnectionMapOutput
}

type RegistryConnectionMap map[string]RegistryConnectionInput

func (RegistryConnectionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RegistryConnection)(nil)).Elem()
}

func (i RegistryConnectionMap) ToRegistryConnectionMapOutput() RegistryConnectionMapOutput {
	return i.ToRegistryConnectionMapOutputWithContext(context.Background())
}

func (i RegistryConnectionMap) ToRegistryConnectionMapOutputWithContext(ctx context.Context) RegistryConnectionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RegistryConnectionMapOutput)
}

type RegistryConnectionOutput struct{ *pulumi.OutputState }

func (RegistryConnectionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**RegistryConnection)(nil)).Elem()
}

func (o RegistryConnectionOutput) ToRegistryConnectionOutput() RegistryConnectionOutput {
	return o
}

func (o RegistryConnectionOutput) ToRegistryConnectionOutputWithContext(ctx context.Context) RegistryConnectionOutput {
	return o
}

type RegistryConnectionArrayOutput struct{ *pulumi.OutputState }

func (RegistryConnectionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RegistryConnection)(nil)).Elem()
}

func (o RegistryConnectionArrayOutput) ToRegistryConnectionArrayOutput() RegistryConnectionArrayOutput {
	return o
}

func (o RegistryConnectionArrayOutput) ToRegistryConnectionArrayOutputWithContext(ctx context.Context) RegistryConnectionArrayOutput {
	return o
}

func (o RegistryConnectionArrayOutput) Index(i pulumi.IntInput) RegistryConnectionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *RegistryConnection {
		return vs[0].([]*RegistryConnection)[vs[1].(int)]
	}).(RegistryConnectionOutput)
}

type RegistryConnectionMapOutput struct{ *pulumi.OutputState }

func (RegistryConnectionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RegistryConnection)(nil)).Elem()
}

func (o RegistryConnectionMapOutput) ToRegistryConnectionMapOutput() RegistryConnectionMapOutput {
	return o
}

func (o RegistryConnectionMapOutput) ToRegistryConnectionMapOutputWithContext(ctx context.Context) RegistryConnectionMapOutput {
	return o
}

func (o RegistryConnectionMapOutput) MapIndex(k pulumi.StringInput) RegistryConnectionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *RegistryConnection {
		return vs[0].(map[string]*RegistryConnection)[vs[1].(string)]
	}).(RegistryConnectionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*RegistryConnectionInput)(nil)).Elem(), &RegistryConnection{})
	pulumi.RegisterInputType(reflect.TypeOf((*RegistryConnectionArrayInput)(nil)).Elem(), RegistryConnectionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*RegistryConnectionMapInput)(nil)).Elem(), RegistryConnectionMap{})
	pulumi.RegisterOutputType(RegistryConnectionOutput{})
	pulumi.RegisterOutputType(RegistryConnectionArrayOutput{})
	pulumi.RegisterOutputType(RegistryConnectionMapOutput{})
}
