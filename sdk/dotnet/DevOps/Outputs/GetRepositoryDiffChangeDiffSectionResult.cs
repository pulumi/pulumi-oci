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
    public sealed class GetRepositoryDiffChangeDiffSectionResult
    {
        /// <summary>
        /// The lines within changed section.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositoryDiffChangeDiffSectionLineResult> Lines;
        /// <summary>
        /// Type of change.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private GetRepositoryDiffChangeDiffSectionResult(
            ImmutableArray<Outputs.GetRepositoryDiffChangeDiffSectionLineResult> lines,

            string type)
        {
            Lines = lines;
            Type = type;
        }
    }
}