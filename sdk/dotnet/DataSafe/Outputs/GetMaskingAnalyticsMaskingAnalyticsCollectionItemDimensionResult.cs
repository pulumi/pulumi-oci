// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimensionResult
    {
        /// <summary>
        /// The OCID of the masking policy..
        /// </summary>
        public readonly string PolicyId;
        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        public readonly string TargetId;

        [OutputConstructor]
        private GetMaskingAnalyticsMaskingAnalyticsCollectionItemDimensionResult(
            string policyId,

            string targetId)
        {
            PolicyId = policyId;
            TargetId = targetId;
        }
    }
}