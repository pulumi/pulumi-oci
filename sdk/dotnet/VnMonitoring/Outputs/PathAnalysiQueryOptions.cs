// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.VnMonitoring.Outputs
{

    [OutputType]
    public sealed class PathAnalysiQueryOptions
    {
        /// <summary>
        /// If true, a path analysis is done for both the forward and reverse routes.
        /// </summary>
        public readonly bool? IsBiDirectionalAnalysis;

        [OutputConstructor]
        private PathAnalysiQueryOptions(bool? isBiDirectionalAnalysis)
        {
            IsBiDirectionalAnalysis = isBiDirectionalAnalysis;
        }
    }
}