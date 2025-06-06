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
    public sealed class GetNamespaceLookupFieldResult
    {
        /// <summary>
        /// The common field name.
        /// </summary>
        public readonly string CommonFieldName;
        /// <summary>
        /// The default match value.
        /// </summary>
        public readonly string DefaultMatchValue;
        /// <summary>
        /// The field display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// A flag indicating whether or not the lookup field is a common field.
        /// </summary>
        public readonly bool IsCommonField;
        /// <summary>
        /// The match operator.
        /// </summary>
        public readonly string MatchOperator;
        /// <summary>
        /// The field name.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// THe field position.
        /// </summary>
        public readonly string Position;

        [OutputConstructor]
        private GetNamespaceLookupFieldResult(
            string commonFieldName,

            string defaultMatchValue,

            string displayName,

            bool isCommonField,

            string matchOperator,

            string name,

            string position)
        {
            CommonFieldName = commonFieldName;
            DefaultMatchValue = defaultMatchValue;
            DisplayName = displayName;
            IsCommonField = isCommonField;
            MatchOperator = matchOperator;
            Name = name;
            Position = position;
        }
    }
}
