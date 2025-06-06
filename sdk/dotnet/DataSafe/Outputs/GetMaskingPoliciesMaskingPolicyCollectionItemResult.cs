// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetMaskingPoliciesMaskingPolicyCollectionItemResult
    {
        public readonly int AddMaskingColumnsFromSdmTrigger;
        /// <summary>
        /// The source of masking columns.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMaskingPoliciesMaskingPolicyCollectionItemColumnSourceResult> ColumnSources;
        /// <summary>
        /// A filter to return only resources that match the specified compartment OCID.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The description of the masking policy.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return only resources that match the specified display name.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        public readonly int GenerateHealthReportTrigger;
        /// <summary>
        /// The OCID of the masking policy.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
        /// </summary>
        public readonly bool IsDropTempTablesEnabled;
        /// <summary>
        /// Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
        /// </summary>
        public readonly bool IsRedoLoggingEnabled;
        /// <summary>
        /// Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
        /// </summary>
        public readonly bool IsRefreshStatsEnabled;
        /// <summary>
        /// Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
        /// </summary>
        public readonly string ParallelDegree;
        /// <summary>
        /// A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
        /// </summary>
        public readonly string PostMaskingScript;
        /// <summary>
        /// A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
        /// </summary>
        public readonly string PreMaskingScript;
        /// <summary>
        /// Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
        /// </summary>
        public readonly string Recompile;
        /// <summary>
        /// A filter to return only the resources that match the specified lifecycle states.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the masking policy was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the masking policy was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMaskingPoliciesMaskingPolicyCollectionItemResult(
            int addMaskingColumnsFromSdmTrigger,

            ImmutableArray<Outputs.GetMaskingPoliciesMaskingPolicyCollectionItemColumnSourceResult> columnSources,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            int generateHealthReportTrigger,

            string id,

            bool isDropTempTablesEnabled,

            bool isRedoLoggingEnabled,

            bool isRefreshStatsEnabled,

            string parallelDegree,

            string postMaskingScript,

            string preMaskingScript,

            string recompile,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            AddMaskingColumnsFromSdmTrigger = addMaskingColumnsFromSdmTrigger;
            ColumnSources = columnSources;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            GenerateHealthReportTrigger = generateHealthReportTrigger;
            Id = id;
            IsDropTempTablesEnabled = isDropTempTablesEnabled;
            IsRedoLoggingEnabled = isRedoLoggingEnabled;
            IsRefreshStatsEnabled = isRefreshStatsEnabled;
            ParallelDegree = parallelDegree;
            PostMaskingScript = postMaskingScript;
            PreMaskingScript = preMaskingScript;
            Recompile = recompile;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
