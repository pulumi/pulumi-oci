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
    public sealed class GetRegistryDataAssetDefaultConnectionPrimarySchemaResult
    {
        /// <summary>
        /// The default connection key.
        /// </summary>
        public readonly string DefaultConnection;
        /// <summary>
        /// A user defined description for the object.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The external key for the object.
        /// </summary>
        public readonly string ExternalKey;
        /// <summary>
        /// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string Identifier;
        /// <summary>
        /// Specifies whether the schema has containers.
        /// </summary>
        public readonly bool IsHasContainers;
        /// <summary>
        /// The identifying key for the object.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// A summary type containing information about the object including its key, name and when/who created/updated it.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaMetadataResult> Metadatas;
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
        /// A reference to the object's parent.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaParentRefResult> ParentReves;
        /// <summary>
        /// A resource name can have letters, numbers, and special characters. The value is editable and is restricted to 4000 characters.
        /// </summary>
        public readonly string ResourceName;

        [OutputConstructor]
        private GetRegistryDataAssetDefaultConnectionPrimarySchemaResult(
            string defaultConnection,

            string description,

            string externalKey,

            string identifier,

            bool isHasContainers,

            string key,

            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaMetadataResult> metadatas,

            string modelType,

            string modelVersion,

            string name,

            int objectStatus,

            int objectVersion,

            ImmutableArray<Outputs.GetRegistryDataAssetDefaultConnectionPrimarySchemaParentRefResult> parentReves,

            string resourceName)
        {
            DefaultConnection = defaultConnection;
            Description = description;
            ExternalKey = externalKey;
            Identifier = identifier;
            IsHasContainers = isHasContainers;
            Key = key;
            Metadatas = metadatas;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
            ObjectVersion = objectVersion;
            ParentReves = parentReves;
            ResourceName = resourceName;
        }
    }
}