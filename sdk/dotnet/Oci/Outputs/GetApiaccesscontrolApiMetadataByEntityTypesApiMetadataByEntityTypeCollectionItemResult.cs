// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemResult
    {
        /// <summary>
        /// List of apiMetadataSummary.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemApiMetadataResult> ApiMetadatas;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The entity Type to which the Api belongs to.
        /// </summary>
        public readonly string EntityType;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;

        [OutputConstructor]
        private GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemResult(
            ImmutableArray<Outputs.GetApiaccesscontrolApiMetadataByEntityTypesApiMetadataByEntityTypeCollectionItemApiMetadataResult> apiMetadatas,

            ImmutableDictionary<string, string> definedTags,

            string entityType,

            ImmutableDictionary<string, string> freeformTags,

            ImmutableDictionary<string, string> systemTags)
        {
            ApiMetadatas = apiMetadatas;
            DefinedTags = definedTags;
            EntityType = entityType;
            FreeformTags = freeformTags;
            SystemTags = systemTags;
        }
    }
}
