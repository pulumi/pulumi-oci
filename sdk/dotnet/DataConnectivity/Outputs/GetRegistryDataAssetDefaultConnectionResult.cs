// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataConnectivity.Outputs
{

    [OutputType]
    public sealed class GetRegistryDataAssetDefaultConnectionResult
    {
        /// <summary>
        /// The properties for the connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionConnectionPropertyResult> ConnectionProperties;
        /// <summary>
        /// A user defined description for the object.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string Identifier;
        /// <summary>
        /// The default property for the connection.
        /// </summary>
        public readonly bool IsDefault;
        /// <summary>
        /// The identifying key for the object.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionMetadataResult> Metadatas;
        /// <summary>
        /// The property which disciminates the subtypes.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// The model version of an object.
        /// </summary>
        public readonly string ModelVersion;
        /// <summary>
        /// Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        public readonly int ObjectStatus;
        /// <summary>
        /// The version of the object that is used to track changes in the object instance.
        /// </summary>
        public readonly int ObjectVersion;
        /// <summary>
        /// The schema object.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaResult> PrimarySchemas;
        /// <summary>
        /// All the properties for the data asset in a key-value map format.
        /// </summary>
        public readonly ImmutableDictionary<string, object> Properties;
        /// <summary>
        /// Information about the object and its parent.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionRegistryMetadataResult> RegistryMetadatas;
        /// <summary>
        /// Specific DataAsset Type
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetRegistryDataAssetDefaultConnectionResult(
            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionConnectionPropertyResult> connectionProperties,

            string description,

            string identifier,

            bool isDefault,

            string key,

            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionMetadataResult> metadatas,

            string modelType,

            string modelVersion,

            string name,

            int objectStatus,

            int objectVersion,

            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaResult> primarySchemas,

            ImmutableDictionary<string, object> properties,

            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionRegistryMetadataResult> registryMetadatas,

            string type)
        {
            ConnectionProperties = connectionProperties;
            Description = description;
            Identifier = identifier;
            IsDefault = isDefault;
            Key = key;
            Metadatas = metadatas;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
            ObjectVersion = objectVersion;
            PrimarySchemas = primarySchemas;
            Properties = properties;
            RegistryMetadatas = registryMetadatas;
            Type = type;
        }
    }
}