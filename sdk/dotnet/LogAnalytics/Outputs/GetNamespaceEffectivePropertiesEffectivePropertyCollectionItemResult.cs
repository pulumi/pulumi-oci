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
    public sealed class GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemResult
    {
        /// <summary>
        /// The effective level of the property value.
        /// </summary>
        public readonly string EffectiveLevel;
        /// <summary>
        /// The property name used for filtering.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// A list of pattern level override values for the property.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPatternResult> Patterns;
        /// <summary>
        /// The effective value of the property. This is determined by considering the value set at the most effective level.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemResult(
            string effectiveLevel,

            string name,

            ImmutableArray<Outputs.GetNamespaceEffectivePropertiesEffectivePropertyCollectionItemPatternResult> patterns,

            string value)
        {
            EffectiveLevel = effectiveLevel;
            Name = name;
            Patterns = patterns;
            Value = value;
        }
    }
}
