// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiLanguage.Outputs
{

    [OutputType]
    public sealed class ModelTestStrategyTestingDataset
    {
        /// <summary>
        /// Data Science Labelling Service OCID
        /// </summary>
        public readonly string? DatasetId;
        /// <summary>
        /// Possible data sets
        /// </summary>
        public readonly string DatasetType;
        /// <summary>
        /// Possible object storage location types
        /// </summary>
        public readonly Outputs.ModelTestStrategyTestingDatasetLocationDetails? LocationDetails;

        [OutputConstructor]
        private ModelTestStrategyTestingDataset(
            string? datasetId,

            string datasetType,

            Outputs.ModelTestStrategyTestingDatasetLocationDetails? locationDetails)
        {
            DatasetId = datasetId;
            DatasetType = datasetType;
            LocationDetails = locationDetails;
        }
    }
}
