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
    public sealed class RegistryDataAssetDefaultConnectionPrimarySchemaMetadataAggregator
    {
        /// <summary>
        /// (Updatable) A user defined description for the object.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Value can only contain upper case letters, underscore, and numbers. It should begin with upper case letter or underscore. The value can be modified.
        /// </summary>
        public readonly string? Identifier;
        /// <summary>
        /// (Updatable) The identifying key for the object.
        /// </summary>
        public readonly string? Key;
        /// <summary>
        /// (Updatable) Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) Specific DataAsset Type
        /// </summary>
        public readonly string? Type;

        [OutputConstructor]
        private RegistryDataAssetDefaultConnectionPrimarySchemaMetadataAggregator(
            string? description,

            string? identifier,

            string? key,

            string? name,

            string? type)
        {
            Description = description;
            Identifier = identifier;
            Key = key;
            Name = name;
            Type = type;
        }
    }
}
