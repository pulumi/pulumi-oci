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
    public sealed class GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemResult
    {
        /// <summary>
        /// User-defined description for the folder.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string Identifier;
        /// <summary>
        /// Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// The type of the folder.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// The model version of an object.
        /// </summary>
        public readonly string ModelVersion;
        /// <summary>
        /// Used to filter by the name of the object.
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
        public readonly Outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemParentRefResult ParentRef;
        /// <summary>
        /// The type system to map from.
        /// </summary>
        public readonly ImmutableDictionary<string, object> TypeMappingFrom;
        /// <summary>
        /// The type system to map to.
        /// </summary>
        public readonly ImmutableDictionary<string, object> TypeMappingTo;
        /// <summary>
        /// An array of types.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeResult> Types;

        [OutputConstructor]
        private GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemResult(
            string description,

            string identifier,

            string key,

            string modelType,

            string modelVersion,

            string name,

            int objectStatus,

            int objectVersion,

            Outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemParentRefResult parentRef,

            ImmutableDictionary<string, object> typeMappingFrom,

            ImmutableDictionary<string, object> typeMappingTo,

            ImmutableArray<Outputs.GetRegistryFoldersFolderSummaryCollectionItemDataAssetNativeTypeSystemTypeResult> types)
        {
            Description = description;
            Identifier = identifier;
            Key = key;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
            ObjectVersion = objectVersion;
            ParentRef = parentRef;
            TypeMappingFrom = typeMappingFrom;
            TypeMappingTo = typeMappingTo;
            Types = types;
        }
    }
}