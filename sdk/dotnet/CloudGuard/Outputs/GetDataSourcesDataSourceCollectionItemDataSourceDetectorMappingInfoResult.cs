// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetDataSourcesDataSourceCollectionItemDataSourceDetectorMappingInfoResult
    {
        /// <summary>
        /// Id of the attached detectorRecipeId to the Data Source.
        /// </summary>
        public readonly string DetectorRecipeId;
        /// <summary>
        /// Id of the attached detectorRuleId to the Data Source.
        /// </summary>
        public readonly string DetectorRuleId;

        [OutputConstructor]
        private GetDataSourcesDataSourceCollectionItemDataSourceDetectorMappingInfoResult(
            string detectorRecipeId,

            string detectorRuleId)
        {
            DetectorRecipeId = detectorRecipeId;
            DetectorRuleId = detectorRuleId;
        }
    }
}