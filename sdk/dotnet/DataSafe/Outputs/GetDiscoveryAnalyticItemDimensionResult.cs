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
    public sealed class GetDiscoveryAnalyticItemDimensionResult
    {
        /// <summary>
        /// A filter to return only the resources that match the specified sensitive data model OCID.
        /// </summary>
        public readonly string SensitiveDataModelId;
        /// <summary>
        /// A filter to return only items related to a specific target OCID.
        /// </summary>
        public readonly string TargetId;

        [OutputConstructor]
        private GetDiscoveryAnalyticItemDimensionResult(
            string sensitiveDataModelId,

            string targetId)
        {
            SensitiveDataModelId = sensitiveDataModelId;
            TargetId = targetId;
        }
    }
}
