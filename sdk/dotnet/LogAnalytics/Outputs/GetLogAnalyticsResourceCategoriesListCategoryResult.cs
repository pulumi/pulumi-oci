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
    public sealed class GetLogAnalyticsResourceCategoriesListCategoryResult
    {
        /// <summary>
        /// The category description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The category display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The system flag. A value of false denotes a user-created category assignment. A value of true denotes an Oracle-defined category assignment.
        /// </summary>
        public readonly bool IsSystem;
        /// <summary>
        /// The unique name that identifies the category.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The category type. Values include "PRODUCT", "TIER", "VENDOR" and "GENERIC".
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetLogAnalyticsResourceCategoriesListCategoryResult(
            string description,

            string displayName,

            bool isSystem,

            string name,

            string type)
        {
            Description = description;
            DisplayName = displayName;
            IsSystem = isSystem;
            Name = name;
            Type = type;
        }
    }
}
