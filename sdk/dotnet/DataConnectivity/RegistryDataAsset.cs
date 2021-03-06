// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity
{
    /// <summary>
    /// This resource provides the Registry Data Asset resource in Oracle Cloud Infrastructure Data Connectivity service.
    /// 
    /// Creates a data asset with default connection.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testRegistryDataAsset = new Oci.DataConnectivity.RegistryDataAsset("testRegistryDataAsset", new Oci.DataConnectivity.RegistryDataAssetArgs
    ///         {
    ///             Identifier = @var.Registry_data_asset_identifier,
    ///             Properties = @var.Registry_data_asset_properties,
    ///             RegistryId = oci_data_connectivity_registry.Test_registry.Id,
    ///             Type = @var.Registry_data_asset_type,
    ///             AssetProperties = @var.Registry_data_asset_asset_properties,
    ///             DefaultConnection = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionArgs
    ///             {
    ///                 Identifier = @var.Registry_data_asset_default_connection_identifier,
    ///                 Key = @var.Registry_data_asset_default_connection_key,
    ///                 Name = @var.Registry_data_asset_default_connection_name,
    ///                 ConnectionProperties = 
    ///                 {
    ///                     new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionConnectionPropertyArgs
    ///                     {
    ///                         Name = @var.Registry_data_asset_default_connection_connection_properties_name,
    ///                         Value = @var.Registry_data_asset_default_connection_connection_properties_value,
    ///                     },
    ///                 },
    ///                 Description = @var.Registry_data_asset_default_connection_description,
    ///                 IsDefault = @var.Registry_data_asset_default_connection_is_default,
    ///                 Metadata = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionMetadataArgs
    ///                 {
    ///                     Aggregator = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionMetadataAggregatorArgs
    ///                     {
    ///                         Description = @var.Registry_data_asset_default_connection_metadata_aggregator_description,
    ///                         Identifier = @var.Registry_data_asset_default_connection_metadata_aggregator_identifier,
    ///                         Key = @var.Registry_data_asset_default_connection_metadata_aggregator_key,
    ///                         Name = @var.Registry_data_asset_default_connection_metadata_aggregator_name,
    ///                         Type = @var.Registry_data_asset_default_connection_metadata_aggregator_type,
    ///                     },
    ///                     AggregatorKey = @var.Registry_data_asset_default_connection_metadata_aggregator_key,
    ///                     CreatedBy = @var.Registry_data_asset_default_connection_metadata_created_by,
    ///                     CreatedByName = @var.Registry_data_asset_default_connection_metadata_created_by_name,
    ///                     IdentifierPath = @var.Registry_data_asset_default_connection_metadata_identifier_path,
    ///                     InfoFields = @var.Registry_data_asset_default_connection_metadata_info_fields,
    ///                     IsFavorite = @var.Registry_data_asset_default_connection_metadata_is_favorite,
    ///                     Labels = @var.Registry_data_asset_default_connection_metadata_labels,
    ///                     RegistryVersion = @var.Registry_data_asset_default_connection_metadata_registry_version,
    ///                     TimeCreated = @var.Registry_data_asset_default_connection_metadata_time_created,
    ///                     TimeUpdated = @var.Registry_data_asset_default_connection_metadata_time_updated,
    ///                     UpdatedBy = @var.Registry_data_asset_default_connection_metadata_updated_by,
    ///                     UpdatedByName = @var.Registry_data_asset_default_connection_metadata_updated_by_name,
    ///                 },
    ///                 ModelType = @var.Registry_data_asset_default_connection_model_type,
    ///                 ModelVersion = @var.Registry_data_asset_default_connection_model_version,
    ///                 ObjectStatus = @var.Registry_data_asset_default_connection_object_status,
    ///                 ObjectVersion = @var.Registry_data_asset_default_connection_object_version,
    ///                 PrimarySchema = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionPrimarySchemaArgs
    ///                 {
    ///                     Identifier = @var.Registry_data_asset_default_connection_primary_schema_identifier,
    ///                     Key = @var.Registry_data_asset_default_connection_primary_schema_key,
    ///                     ModelType = @var.Registry_data_asset_default_connection_primary_schema_model_type,
    ///                     Name = @var.Registry_data_asset_default_connection_primary_schema_name,
    ///                     DefaultConnection = @var.Registry_data_asset_default_connection_primary_schema_default_connection,
    ///                     Description = @var.Registry_data_asset_default_connection_primary_schema_description,
    ///                     ExternalKey = @var.Registry_data_asset_default_connection_primary_schema_external_key,
    ///                     IsHasContainers = @var.Registry_data_asset_default_connection_primary_schema_is_has_containers,
    ///                     Metadata = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionPrimarySchemaMetadataArgs
    ///                     {
    ///                         Aggregator = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionPrimarySchemaMetadataAggregatorArgs
    ///                         {
    ///                             Description = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_description,
    ///                             Identifier = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_identifier,
    ///                             Key = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_key,
    ///                             Name = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_name,
    ///                             Type = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_type,
    ///                         },
    ///                         AggregatorKey = @var.Registry_data_asset_default_connection_primary_schema_metadata_aggregator_key,
    ///                         CreatedBy = @var.Registry_data_asset_default_connection_primary_schema_metadata_created_by,
    ///                         CreatedByName = @var.Registry_data_asset_default_connection_primary_schema_metadata_created_by_name,
    ///                         IdentifierPath = @var.Registry_data_asset_default_connection_primary_schema_metadata_identifier_path,
    ///                         InfoFields = @var.Registry_data_asset_default_connection_primary_schema_metadata_info_fields,
    ///                         IsFavorite = @var.Registry_data_asset_default_connection_primary_schema_metadata_is_favorite,
    ///                         Labels = @var.Registry_data_asset_default_connection_primary_schema_metadata_labels,
    ///                         RegistryVersion = @var.Registry_data_asset_default_connection_primary_schema_metadata_registry_version,
    ///                         TimeCreated = @var.Registry_data_asset_default_connection_primary_schema_metadata_time_created,
    ///                         TimeUpdated = @var.Registry_data_asset_default_connection_primary_schema_metadata_time_updated,
    ///                         UpdatedBy = @var.Registry_data_asset_default_connection_primary_schema_metadata_updated_by,
    ///                         UpdatedByName = @var.Registry_data_asset_default_connection_primary_schema_metadata_updated_by_name,
    ///                     },
    ///                     ModelVersion = @var.Registry_data_asset_default_connection_primary_schema_model_version,
    ///                     ObjectStatus = @var.Registry_data_asset_default_connection_primary_schema_object_status,
    ///                     ObjectVersion = @var.Registry_data_asset_default_connection_primary_schema_object_version,
    ///                     ParentRef = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionPrimarySchemaParentRefArgs
    ///                     {
    ///                         Parent = @var.Registry_data_asset_default_connection_primary_schema_parent_ref_parent,
    ///                     },
    ///                     ResourceName = @var.Registry_data_asset_default_connection_primary_schema_resource_name,
    ///                 },
    ///                 Properties = @var.Registry_data_asset_default_connection_properties,
    ///                 RegistryMetadata = new Oci.DataConnectivity.Inputs.RegistryDataAssetDefaultConnectionRegistryMetadataArgs
    ///                 {
    ///                     AggregatorKey = @var.Registry_data_asset_default_connection_registry_metadata_aggregator_key,
    ///                     CreatedByUserId = oci_identity_user.Test_user.Id,
    ///                     CreatedByUserName = oci_identity_user.Test_user.Name,
    ///                     IsFavorite = @var.Registry_data_asset_default_connection_registry_metadata_is_favorite,
    ///                     Key = @var.Registry_data_asset_default_connection_registry_metadata_key,
    ///                     Labels = @var.Registry_data_asset_default_connection_registry_metadata_labels,
    ///                     RegistryVersion = @var.Registry_data_asset_default_connection_registry_metadata_registry_version,
    ///                     TimeCreated = @var.Registry_data_asset_default_connection_registry_metadata_time_created,
    ///                     TimeUpdated = @var.Registry_data_asset_default_connection_registry_metadata_time_updated,
    ///                     UpdatedByUserId = oci_identity_user.Test_user.Id,
    ///                     UpdatedByUserName = oci_identity_user.Test_user.Name,
    ///                 },
    ///                 Type = @var.Registry_data_asset_default_connection_type,
    ///             },
    ///             Description = @var.Registry_data_asset_description,
    ///             ExternalKey = @var.Registry_data_asset_external_key,
    ///             Key = @var.Registry_data_asset_key,
    ///             Metadata = new Oci.DataConnectivity.Inputs.RegistryDataAssetMetadataArgs
    ///             {
    ///                 Aggregator = new Oci.DataConnectivity.Inputs.RegistryDataAssetMetadataAggregatorArgs
    ///                 {
    ///                     Description = @var.Registry_data_asset_metadata_aggregator_description,
    ///                     Identifier = @var.Registry_data_asset_metadata_aggregator_identifier,
    ///                     Key = @var.Registry_data_asset_metadata_aggregator_key,
    ///                     Name = @var.Registry_data_asset_metadata_aggregator_name,
    ///                     Type = @var.Registry_data_asset_metadata_aggregator_type,
    ///                 },
    ///                 AggregatorKey = @var.Registry_data_asset_metadata_aggregator_key,
    ///                 CreatedBy = @var.Registry_data_asset_metadata_created_by,
    ///                 CreatedByName = @var.Registry_data_asset_metadata_created_by_name,
    ///                 IdentifierPath = @var.Registry_data_asset_metadata_identifier_path,
    ///                 InfoFields = @var.Registry_data_asset_metadata_info_fields,
    ///                 IsFavorite = @var.Registry_data_asset_metadata_is_favorite,
    ///                 Labels = @var.Registry_data_asset_metadata_labels,
    ///                 RegistryVersion = @var.Registry_data_asset_metadata_registry_version,
    ///                 TimeCreated = @var.Registry_data_asset_metadata_time_created,
    ///                 TimeUpdated = @var.Registry_data_asset_metadata_time_updated,
    ///                 UpdatedBy = @var.Registry_data_asset_metadata_updated_by,
    ///                 UpdatedByName = @var.Registry_data_asset_metadata_updated_by_name,
    ///             },
    ///             ModelType = @var.Registry_data_asset_model_type,
    ///             ModelVersion = @var.Registry_data_asset_model_version,
    ///             NativeTypeSystem = new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemArgs
    ///             {
    ///                 Description = @var.Registry_data_asset_native_type_system_description,
    ///                 Identifier = @var.Registry_data_asset_native_type_system_identifier,
    ///                 Key = @var.Registry_data_asset_native_type_system_key,
    ///                 ModelType = @var.Registry_data_asset_native_type_system_model_type,
    ///                 ModelVersion = @var.Registry_data_asset_native_type_system_model_version,
    ///                 Name = @var.Registry_data_asset_native_type_system_name,
    ///                 ObjectStatus = @var.Registry_data_asset_native_type_system_object_status,
    ///                 ObjectVersion = @var.Registry_data_asset_native_type_system_object_version,
    ///                 ParentRef = new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemParentRefArgs
    ///                 {
    ///                     Parent = @var.Registry_data_asset_native_type_system_parent_ref_parent,
    ///                 },
    ///                 TypeMappingFrom = @var.Registry_data_asset_native_type_system_type_mapping_from,
    ///                 TypeMappingTo = @var.Registry_data_asset_native_type_system_type_mapping_to,
    ///                 Types = 
    ///                 {
    ///                     new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemTypeArgs
    ///                     {
    ///                         ModelType = @var.Registry_data_asset_native_type_system_types_model_type,
    ///                         ConfigDefinition = new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemTypeConfigDefinitionArgs
    ///                         {
    ///                             ConfigParameterDefinitions = 
    ///                             {
    ///                                 
    ///                                 {
    ///                                     { "classFieldName", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_class_field_name },
    ///                                     { "defaultValue", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_default_value },
    ///                                     { "description", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_description },
    ///                                     { "isClassFieldValue", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_is_class_field_value },
    ///                                     { "isStatic", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_is_static },
    ///                                     { "parameterName", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_parameter_name },
    ///                                     { "parameterType", @var.Registry_data_asset_native_type_system_types_config_definition_config_parameter_definitions_parameter_type },
    ///                                 },
    ///                             },
    ///                             IsContained = @var.Registry_data_asset_native_type_system_types_config_definition_is_contained,
    ///                             Key = @var.Registry_data_asset_native_type_system_types_config_definition_key,
    ///                             ModelType = @var.Registry_data_asset_native_type_system_types_config_definition_model_type,
    ///                             ModelVersion = @var.Registry_data_asset_native_type_system_types_config_definition_model_version,
    ///                             Name = @var.Registry_data_asset_native_type_system_types_config_definition_name,
    ///                             ObjectStatus = @var.Registry_data_asset_native_type_system_types_config_definition_object_status,
    ///                             ParentRef = new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemTypeConfigDefinitionParentRefArgs
    ///                             {
    ///                                 Parent = @var.Registry_data_asset_native_type_system_types_config_definition_parent_ref_parent,
    ///                             },
    ///                         },
    ///                         Description = @var.Registry_data_asset_native_type_system_types_description,
    ///                         DtType = @var.Registry_data_asset_native_type_system_types_dt_type,
    ///                         Key = @var.Registry_data_asset_native_type_system_types_key,
    ///                         ModelVersion = @var.Registry_data_asset_native_type_system_types_model_version,
    ///                         Name = @var.Registry_data_asset_native_type_system_types_name,
    ///                         ObjectStatus = @var.Registry_data_asset_native_type_system_types_object_status,
    ///                         ParentRef = new Oci.DataConnectivity.Inputs.RegistryDataAssetNativeTypeSystemTypeParentRefArgs
    ///                         {
    ///                             Parent = @var.Registry_data_asset_native_type_system_types_parent_ref_parent,
    ///                         },
    ///                         TypeSystemName = @var.Registry_data_asset_native_type_system_types_type_system_name,
    ///                     },
    ///                 },
    ///             },
    ///             ObjectStatus = @var.Registry_data_asset_object_status,
    ///             ObjectVersion = @var.Registry_data_asset_object_version,
    ///             RegistryMetadata = new Oci.DataConnectivity.Inputs.RegistryDataAssetRegistryMetadataArgs
    ///             {
    ///                 AggregatorKey = @var.Registry_data_asset_registry_metadata_aggregator_key,
    ///                 CreatedByUserId = oci_identity_user.Test_user.Id,
    ///                 CreatedByUserName = oci_identity_user.Test_user.Name,
    ///                 IsFavorite = @var.Registry_data_asset_registry_metadata_is_favorite,
    ///                 Key = @var.Registry_data_asset_registry_metadata_key,
    ///                 Labels = @var.Registry_data_asset_registry_metadata_labels,
    ///                 RegistryVersion = @var.Registry_data_asset_registry_metadata_registry_version,
    ///                 TimeCreated = @var.Registry_data_asset_registry_metadata_time_created,
    ///                 TimeUpdated = @var.Registry_data_asset_registry_metadata_time_updated,
    ///                 UpdatedByUserId = oci_identity_user.Test_user.Id,
    ///                 UpdatedByUserName = oci_identity_user.Test_user.Name,
    ///             },
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// RegistryDataAssets can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:DataConnectivity/registryDataAsset:RegistryDataAsset test_registry_data_asset "registries/{registryId}/dataAssets/{dataAssetKey}"
    /// ```
    /// </summary>
    [OciResourceType("oci:DataConnectivity/registryDataAsset:RegistryDataAsset")]
    public partial class RegistryDataAsset : Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) Additional properties for the data asset.
        /// </summary>
        [Output("assetProperties")]
        public Output<ImmutableDictionary<string, object>> AssetProperties { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The default connection key.
        /// </summary>
        [Output("defaultConnection")]
        public Output<Outputs.RegistryDataAssetDefaultConnection> DefaultConnection { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user defined description for the object.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The external key for the object.
        /// </summary>
        [Output("externalKey")]
        public Output<string> ExternalKey { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        [Output("identifier")]
        public Output<string> Identifier { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The identifying key for the object.
        /// </summary>
        [Output("key")]
        public Output<string> Key { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        [Output("metadata")]
        public Output<Outputs.RegistryDataAssetMetadata> Metadata { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The property which disciminates the subtypes.
        /// </summary>
        [Output("modelType")]
        public Output<string> ModelType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        [Output("modelVersion")]
        public Output<string> ModelVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        [Output("name")]
        public Output<string> Name { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The type system maps from and to a type.
        /// </summary>
        [Output("nativeTypeSystem")]
        public Output<Outputs.RegistryDataAssetNativeTypeSystem> NativeTypeSystem { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        [Output("objectStatus")]
        public Output<int> ObjectStatus { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The version of the object that is used to track changes in the object instance.
        /// </summary>
        [Output("objectVersion")]
        public Output<int> ObjectVersion { get; private set; } = null!;

        /// <summary>
        /// (Updatable) All the properties for the data asset in a key-value map format.
        /// </summary>
        [Output("properties")]
        public Output<ImmutableDictionary<string, object>> Properties { get; private set; } = null!;

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Output("registryId")]
        public Output<string> RegistryId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Information about the object and its parent.
        /// </summary>
        [Output("registryMetadata")]
        public Output<Outputs.RegistryDataAssetRegistryMetadata> RegistryMetadata { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Specific DataAsset Type
        /// </summary>
        [Output("type")]
        public Output<string> Type { get; private set; } = null!;


        /// <summary>
        /// Create a RegistryDataAsset resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public RegistryDataAsset(string name, RegistryDataAssetArgs args, CustomResourceOptions? options = null)
            : base("oci:DataConnectivity/registryDataAsset:RegistryDataAsset", name, args ?? new RegistryDataAssetArgs(), MakeResourceOptions(options, ""))
        {
        }

        private RegistryDataAsset(string name, Input<string> id, RegistryDataAssetState? state = null, CustomResourceOptions? options = null)
            : base("oci:DataConnectivity/registryDataAsset:RegistryDataAsset", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing RegistryDataAsset resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static RegistryDataAsset Get(string name, Input<string> id, RegistryDataAssetState? state = null, CustomResourceOptions? options = null)
        {
            return new RegistryDataAsset(name, id, state, options);
        }
    }

    public sealed class RegistryDataAssetArgs : Pulumi.ResourceArgs
    {
        [Input("assetProperties")]
        private InputMap<object>? _assetProperties;

        /// <summary>
        /// (Updatable) Additional properties for the data asset.
        /// </summary>
        public InputMap<object> AssetProperties
        {
            get => _assetProperties ?? (_assetProperties = new InputMap<object>());
            set => _assetProperties = value;
        }

        /// <summary>
        /// (Updatable) The default connection key.
        /// </summary>
        [Input("defaultConnection")]
        public Input<Inputs.RegistryDataAssetDefaultConnectionArgs>? DefaultConnection { get; set; }

        /// <summary>
        /// (Updatable) A user defined description for the object.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The external key for the object.
        /// </summary>
        [Input("externalKey")]
        public Input<string>? ExternalKey { get; set; }

        /// <summary>
        /// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        [Input("identifier", required: true)]
        public Input<string> Identifier { get; set; } = null!;

        /// <summary>
        /// (Updatable) The identifying key for the object.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        [Input("metadata")]
        public Input<Inputs.RegistryDataAssetMetadataArgs>? Metadata { get; set; }

        /// <summary>
        /// (Updatable) The property which disciminates the subtypes.
        /// </summary>
        [Input("modelType", required: true)]
        public Input<string> ModelType { get; set; } = null!;

        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        [Input("modelVersion")]
        public Input<string>? ModelVersion { get; set; }

        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The type system maps from and to a type.
        /// </summary>
        [Input("nativeTypeSystem")]
        public Input<Inputs.RegistryDataAssetNativeTypeSystemArgs>? NativeTypeSystem { get; set; }

        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        [Input("objectStatus")]
        public Input<int>? ObjectStatus { get; set; }

        /// <summary>
        /// (Updatable) The version of the object that is used to track changes in the object instance.
        /// </summary>
        [Input("objectVersion")]
        public Input<int>? ObjectVersion { get; set; }

        [Input("properties", required: true)]
        private InputMap<object>? _properties;

        /// <summary>
        /// (Updatable) All the properties for the data asset in a key-value map format.
        /// </summary>
        public InputMap<object> Properties
        {
            get => _properties ?? (_properties = new InputMap<object>());
            set => _properties = value;
        }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId", required: true)]
        public Input<string> RegistryId { get; set; } = null!;

        /// <summary>
        /// (Updatable) Information about the object and its parent.
        /// </summary>
        [Input("registryMetadata")]
        public Input<Inputs.RegistryDataAssetRegistryMetadataArgs>? RegistryMetadata { get; set; }

        /// <summary>
        /// (Updatable) Specific DataAsset Type
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        public RegistryDataAssetArgs()
        {
        }
    }

    public sealed class RegistryDataAssetState : Pulumi.ResourceArgs
    {
        [Input("assetProperties")]
        private InputMap<object>? _assetProperties;

        /// <summary>
        /// (Updatable) Additional properties for the data asset.
        /// </summary>
        public InputMap<object> AssetProperties
        {
            get => _assetProperties ?? (_assetProperties = new InputMap<object>());
            set => _assetProperties = value;
        }

        /// <summary>
        /// (Updatable) The default connection key.
        /// </summary>
        [Input("defaultConnection")]
        public Input<Inputs.RegistryDataAssetDefaultConnectionGetArgs>? DefaultConnection { get; set; }

        /// <summary>
        /// (Updatable) A user defined description for the object.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) The external key for the object.
        /// </summary>
        [Input("externalKey")]
        public Input<string>? ExternalKey { get; set; }

        /// <summary>
        /// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        [Input("identifier")]
        public Input<string>? Identifier { get; set; }

        /// <summary>
        /// (Updatable) The identifying key for the object.
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        [Input("metadata")]
        public Input<Inputs.RegistryDataAssetMetadataGetArgs>? Metadata { get; set; }

        /// <summary>
        /// (Updatable) The property which disciminates the subtypes.
        /// </summary>
        [Input("modelType")]
        public Input<string>? ModelType { get; set; }

        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        [Input("modelVersion")]
        public Input<string>? ModelVersion { get; set; }

        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// (Updatable) The type system maps from and to a type.
        /// </summary>
        [Input("nativeTypeSystem")]
        public Input<Inputs.RegistryDataAssetNativeTypeSystemGetArgs>? NativeTypeSystem { get; set; }

        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        [Input("objectStatus")]
        public Input<int>? ObjectStatus { get; set; }

        /// <summary>
        /// (Updatable) The version of the object that is used to track changes in the object instance.
        /// </summary>
        [Input("objectVersion")]
        public Input<int>? ObjectVersion { get; set; }

        [Input("properties")]
        private InputMap<object>? _properties;

        /// <summary>
        /// (Updatable) All the properties for the data asset in a key-value map format.
        /// </summary>
        public InputMap<object> Properties
        {
            get => _properties ?? (_properties = new InputMap<object>());
            set => _properties = value;
        }

        /// <summary>
        /// The registry Ocid.
        /// </summary>
        [Input("registryId")]
        public Input<string>? RegistryId { get; set; }

        /// <summary>
        /// (Updatable) Information about the object and its parent.
        /// </summary>
        [Input("registryMetadata")]
        public Input<Inputs.RegistryDataAssetRegistryMetadataGetArgs>? RegistryMetadata { get; set; }

        /// <summary>
        /// (Updatable) Specific DataAsset Type
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public RegistryDataAssetState()
        {
        }
    }
}
