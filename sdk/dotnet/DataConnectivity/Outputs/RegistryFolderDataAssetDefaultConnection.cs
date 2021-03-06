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
    public sealed class RegistryFolderDataAssetDefaultConnection
    {
        /// <summary>
        /// (Updatable) The properties for the connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.RegistryFolderDataAssetDefaultConnectionConnectionProperty> ConnectionProperties;
        /// <summary>
        /// (Updatable) User-defined description for the folder.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string Identifier;
        /// <summary>
        /// (Updatable) The default property for the connection.
        /// </summary>
        public readonly bool? IsDefault;
        /// <summary>
        /// (Updatable) Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// (Updatable) A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        public readonly Outputs.RegistryFolderDataAssetDefaultConnectionMetadata? Metadata;
        /// <summary>
        /// (Updatable) The type of the folder.
        /// </summary>
        public readonly string? ModelType;
        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        public readonly string? ModelVersion;
        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        public readonly int? ObjectStatus;
        /// <summary>
        /// (Updatable) The version of the object that is used to track changes in the object instance.
        /// </summary>
        public readonly int? ObjectVersion;
        /// <summary>
        /// (Updatable) The schema object.
        /// </summary>
        public readonly Outputs.RegistryFolderDataAssetDefaultConnectionPrimarySchema? PrimarySchema;
        /// <summary>
        /// (Updatable) All the properties for the data asset in a key-value map format.
        /// </summary>
        public readonly ImmutableDictionary<string, object>? Properties;
        /// <summary>
        /// (Updatable) Information about the object and its parent.
        /// </summary>
        public readonly Outputs.RegistryFolderDataAssetDefaultConnectionRegistryMetadata? RegistryMetadata;
        /// <summary>
        /// (Updatable) Specific DataAsset Type
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private RegistryFolderDataAssetDefaultConnection(
            ImmutableArray<Outputs.RegistryFolderDataAssetDefaultConnectionConnectionProperty> connectionProperties,

            string? description,

            string identifier,

            bool? isDefault,

            string key,

            Outputs.RegistryFolderDataAssetDefaultConnectionMetadata? metadata,

            string? modelType,

            string? modelVersion,

            string name,

            int? objectStatus,

            int? objectVersion,

            Outputs.RegistryFolderDataAssetDefaultConnectionPrimarySchema? primarySchema,

            ImmutableDictionary<string, object>? properties,

            Outputs.RegistryFolderDataAssetDefaultConnectionRegistryMetadata? registryMetadata,

            string? type)
        {
            ConnectionProperties = connectionProperties;
            Description = description;
            Identifier = identifier;
            IsDefault = isDefault;
            Key = key;
            Metadata = metadata;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
            ObjectVersion = objectVersion;
            PrimarySchema = primarySchema;
            Properties = properties;
            RegistryMetadata = registryMetadata;
            Type = type;
        }
    }
}
