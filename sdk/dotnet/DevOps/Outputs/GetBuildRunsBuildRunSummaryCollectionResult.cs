// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class GetBuildRunsBuildRunSummaryCollectionResult
    {
        /// <summary>
        /// List of exported variables.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetBuildRunsBuildRunSummaryCollectionItemResult> Items;

        [OutputConstructor]
        private GetBuildRunsBuildRunSummaryCollectionResult(ImmutableArray<Outputs.GetBuildRunsBuildRunSummaryCollectionItemResult> items)
        {
            Items = items;
        }
    }
}