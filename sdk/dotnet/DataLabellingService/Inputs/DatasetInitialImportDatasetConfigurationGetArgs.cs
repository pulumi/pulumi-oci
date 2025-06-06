// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataLabellingService.Inputs
{

    public sealed class DatasetInitialImportDatasetConfigurationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// File format details used for importing dataset
        /// </summary>
        [Input("importFormat", required: true)]
        public Input<Inputs.DatasetInitialImportDatasetConfigurationImportFormatGetArgs> ImportFormat { get; set; } = null!;

        /// <summary>
        /// Object storage path for the metadata file
        /// </summary>
        [Input("importMetadataPath", required: true)]
        public Input<Inputs.DatasetInitialImportDatasetConfigurationImportMetadataPathGetArgs> ImportMetadataPath { get; set; } = null!;

        public DatasetInitialImportDatasetConfigurationGetArgs()
        {
        }
        public static new DatasetInitialImportDatasetConfigurationGetArgs Empty => new DatasetInitialImportDatasetConfigurationGetArgs();
    }
}
