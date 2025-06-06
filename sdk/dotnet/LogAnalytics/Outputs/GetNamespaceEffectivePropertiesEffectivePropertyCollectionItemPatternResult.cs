// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPatternResult
    {
        /// <summary>
        /// The effective level of the property value.
        /// </summary>
        public readonly string EffectiveLevel;
        /// <summary>
        /// The pattern id.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The effective value of the property. This is determined by considering the value set at the most effective level.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPatternResult(
            string effectiveLevel,

            string id,

            string value)
        {
            EffectiveLevel = effectiveLevel;
            Id = id;
            Value = value;
        }
    }
}
