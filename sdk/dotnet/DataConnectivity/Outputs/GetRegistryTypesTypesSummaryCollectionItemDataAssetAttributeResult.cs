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
    public sealed class GetRegistryTypesTypesSummaryCollectionItemDataAssetAttributeResult
    {
        /// <summary>
        /// Attribute type details
        /// </summary>
        public readonly string AttributeType;
        /// <summary>
        /// True if Attribute is encoded.
        /// </summary>
        public readonly bool IsBase64encoded;
        /// <summary>
        /// True if Attribute is generated.
        /// </summary>
        public readonly bool IsGenerated;
        /// <summary>
        /// True if Attribute is mandatory.
        /// </summary>
        public readonly bool IsMandatory;
        /// <summary>
        /// True if Attribute is sensitive.
        /// </summary>
        public readonly bool IsSensitive;
        /// <summary>
        /// Used to filter by the name of the object.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// List of valid key list
        /// </summary>
        public readonly ImmutableArray<string> ValidKeyLists;

        [OutputConstructor]
        private GetRegistryTypesTypesSummaryCollectionItemDataAssetAttributeResult(
            string attributeType,

            bool isBase64encoded,

            bool isGenerated,

            bool isMandatory,

            bool isSensitive,

            string name,

            ImmutableArray<string> validKeyLists)
        {
            AttributeType = attributeType;
            IsBase64encoded = isBase64encoded;
            IsGenerated = isGenerated;
            IsMandatory = isMandatory;
            IsSensitive = isSensitive;
            Name = name;
            ValidKeyLists = validKeyLists;
        }
    }
}
