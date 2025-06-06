// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetDetectorRecipeDetectorRuleEntitiesMappingResult
    {
        /// <summary>
        /// Display name of the entity
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Type of entity
        /// </summary>
        public readonly string EntityType;
        /// <summary>
        /// The entity value mapped to a data source query
        /// </summary>
        public readonly string QueryField;

        [OutputConstructor]
        private GetDetectorRecipeDetectorRuleEntitiesMappingResult(
            string displayName,

            string entityType,

            string queryField)
        {
            DisplayName = displayName;
            EntityType = entityType;
            QueryField = queryField;
        }
    }
}
