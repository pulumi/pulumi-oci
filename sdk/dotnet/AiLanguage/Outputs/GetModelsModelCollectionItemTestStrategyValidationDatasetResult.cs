// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Outputs
{

    [OutputType]
    public sealed class GetModelsModelCollectionItemTestStrategyValidationDatasetResult
    {
        /// <summary>
        /// Data Science Labelling Service OCID
        /// </summary>
        public readonly string DatasetId;
        /// <summary>
        /// Possible data sets
        /// </summary>
        public readonly string DatasetType;
        /// <summary>
        /// Possible object storage location types
        /// </summary>
        public readonly ImmutableArray<Outputs.GetModelsModelCollectionItemTestStrategyValidationDatasetLocationDetailResult> LocationDetails;

        [OutputConstructor]
        private GetModelsModelCollectionItemTestStrategyValidationDatasetResult(
            string datasetId,

            string datasetType,

            ImmutableArray<Outputs.GetModelsModelCollectionItemTestStrategyValidationDatasetLocationDetailResult> locationDetails)
        {
            DatasetId = datasetId;
            DatasetType = datasetType;
            LocationDetails = locationDetails;
        }
    }
}