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
    public sealed class RegistryFolderDataAssetNativeTypeSystemType
    {
        /// <summary>
        /// (Updatable) The configuration details of a configurable object. This contains one or more config param definitions.
        /// </summary>
        public readonly Outputs.RegistryFolderDataAssetNativeTypeSystemTypeConfigDefinition? ConfigDefinition;
        /// <summary>
        /// (Updatable) User-defined description for the folder.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) The data type.
        /// </summary>
        public readonly string? DtType;
        /// <summary>
        /// (Updatable) Generated key that can be used in API calls to identify folder. On scenarios where reference to the folder is needed, a value can be passed in create.
        /// </summary>
        public readonly string? Key;
        /// <summary>
        /// (Updatable) The type of the folder.
        /// </summary>
        public readonly string ModelType;
        /// <summary>
        /// (Updatable) The model version of an object.
        /// </summary>
        public readonly string? ModelVersion;
        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) The status of an object that can be set to value 1 for shallow references across objects, other values reserved.
        /// </summary>
        public readonly int? ObjectStatus;
        /// <summary>
        /// (Updatable) A reference to the object's parent.
        /// </summary>
        public readonly Outputs.RegistryFolderDataAssetNativeTypeSystemTypeParentRef? ParentRef;
        /// <summary>
        /// (Updatable) The data type system name.
        /// </summary>
        public readonly string? TypeSystemName;

        [OutputConstructor]
        private RegistryFolderDataAssetNativeTypeSystemType(
            Outputs.RegistryFolderDataAssetNativeTypeSystemTypeConfigDefinition? configDefinition,

            string? description,

            string? dtType,

            string? key,

            string modelType,

            string? modelVersion,

            string? name,

            int? objectStatus,

            Outputs.RegistryFolderDataAssetNativeTypeSystemTypeParentRef? parentRef,

            string? typeSystemName)
        {
            ConfigDefinition = configDefinition;
            Description = description;
            DtType = dtType;
            Key = key;
            ModelType = modelType;
            ModelVersion = modelVersion;
            Name = name;
            ObjectStatus = objectStatus;
            ParentRef = parentRef;
            TypeSystemName = typeSystemName;
        }
    }
}