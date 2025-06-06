// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate.Outputs
{

    [OutputType]
    public sealed class GetPipelineSchemaTablesPipelineSchemaTableCollectionResult
    {
        /// <summary>
        /// Array of source or target schema tables of a pipeline's assigned connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPipelineSchemaTablesPipelineSchemaTableCollectionItemResult> Items;
        /// <summary>
        /// Name of the source schema obtained from get schema endpoint of the created pipeline.
        /// </summary>
        public readonly string SourceSchemaName;
        /// <summary>
        /// Name of the target schema obtained from get schema endpoint of the created pipeline.
        /// </summary>
        public readonly string TargetSchemaName;

        [OutputConstructor]
        private GetPipelineSchemaTablesPipelineSchemaTableCollectionResult(
            ImmutableArray<Outputs.GetPipelineSchemaTablesPipelineSchemaTableCollectionItemResult> items,

            string sourceSchemaName,

            string targetSchemaName)
        {
            Items = items;
            SourceSchemaName = sourceSchemaName;
            TargetSchemaName = targetSchemaName;
        }
    }
}
