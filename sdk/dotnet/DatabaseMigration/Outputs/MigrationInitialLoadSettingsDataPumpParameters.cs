// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Outputs
{

    [OutputType]
    public sealed class MigrationInitialLoadSettingsDataPumpParameters
    {
        /// <summary>
        /// (Updatable) Estimate size of dumps that will be generated.
        /// </summary>
        public readonly string? Estimate;
        /// <summary>
        /// (Updatable) Exclude paratemers for Export and Import.
        /// </summary>
        public readonly ImmutableArray<string> ExcludeParameters;
        /// <summary>
        /// (Updatable) Maximum number of worker processes that can be used for a Data Pump Export job.
        /// </summary>
        public readonly int? ExportParallelismDegree;
        /// <summary>
        /// (Updatable) Maximum number of worker processes that can be used for a Data Pump Import job. For an Autonomous Database, ODMS will automatically query its CPU core count and set this property.
        /// </summary>
        public readonly int? ImportParallelismDegree;
        /// <summary>
        /// (Updatable) Set to false to force Data Pump worker process to run on one instance.
        /// </summary>
        public readonly bool? IsCluster;
        /// <summary>
        /// (Updatable) IMPORT: Specifies the action to be performed when data is loaded into a preexisting table.
        /// </summary>
        public readonly string? TableExistsAction;

        [OutputConstructor]
        private MigrationInitialLoadSettingsDataPumpParameters(
            string? estimate,

            ImmutableArray<string> excludeParameters,

            int? exportParallelismDegree,

            int? importParallelismDegree,

            bool? isCluster,

            string? tableExistsAction)
        {
            Estimate = estimate;
            ExcludeParameters = excludeParameters;
            ExportParallelismDegree = exportParallelismDegree;
            ImportParallelismDegree = importParallelismDegree;
            IsCluster = isCluster;
            TableExistsAction = tableExistsAction;
        }
    }
}
