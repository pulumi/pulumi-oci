// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Outputs
{

    [OutputType]
    public sealed class LogAnalyticsImportCustomContentChangeList
    {
        /// <summary>
        /// A list of field display names with conflicts.
        /// </summary>
        public readonly ImmutableArray<string> ConflictFieldDisplayNames;
        /// <summary>
        /// A list of parser names with conflicts.
        /// </summary>
        public readonly ImmutableArray<string> ConflictParserNames;
        /// <summary>
        /// A list of source names with conflicts.
        /// </summary>
        public readonly ImmutableArray<string> ConflictSourceNames;
        /// <summary>
        /// An array of created field display names.
        /// </summary>
        public readonly ImmutableArray<string> CreatedFieldDisplayNames;
        /// <summary>
        /// An array of created parser names.
        /// </summary>
        public readonly ImmutableArray<string> CreatedParserNames;
        /// <summary>
        /// An array of created source names.
        /// </summary>
        public readonly ImmutableArray<string> CreatedSourceNames;
        /// <summary>
        /// An array of updated field display names.
        /// </summary>
        public readonly ImmutableArray<string> UpdatedFieldDisplayNames;
        /// <summary>
        /// An array of updated parser names.
        /// </summary>
        public readonly ImmutableArray<string> UpdatedParserNames;
        /// <summary>
        /// An array of updated source names.
        /// </summary>
        public readonly ImmutableArray<string> UpdatedSourceNames;

        [OutputConstructor]
        private LogAnalyticsImportCustomContentChangeList(
            ImmutableArray<string> conflictFieldDisplayNames,

            ImmutableArray<string> conflictParserNames,

            ImmutableArray<string> conflictSourceNames,

            ImmutableArray<string> createdFieldDisplayNames,

            ImmutableArray<string> createdParserNames,

            ImmutableArray<string> createdSourceNames,

            ImmutableArray<string> updatedFieldDisplayNames,

            ImmutableArray<string> updatedParserNames,

            ImmutableArray<string> updatedSourceNames)
        {
            ConflictFieldDisplayNames = conflictFieldDisplayNames;
            ConflictParserNames = conflictParserNames;
            ConflictSourceNames = conflictSourceNames;
            CreatedFieldDisplayNames = createdFieldDisplayNames;
            CreatedParserNames = createdParserNames;
            CreatedSourceNames = createdSourceNames;
            UpdatedFieldDisplayNames = updatedFieldDisplayNames;
            UpdatedParserNames = updatedParserNames;
            UpdatedSourceNames = updatedSourceNames;
        }
    }
}