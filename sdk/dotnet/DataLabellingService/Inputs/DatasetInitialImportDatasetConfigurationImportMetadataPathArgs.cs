// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataLabellingService.Inputs
{

    public sealed class DatasetInitialImportDatasetConfigurationImportMetadataPathArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Bucket name
        /// </summary>
        [Input("bucket", required: true)]
        public Input<string> Bucket { get; set; } = null!;

        /// <summary>
        /// Bucket namespace name
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// Path for the metadata file.
        /// </summary>
        [Input("path", required: true)]
        public Input<string> Path { get; set; } = null!;

        /// <summary>
        /// The type of data source. OBJECT_STORAGE - The source details for an object storage bucket.
        /// </summary>
        [Input("sourceType", required: true)]
        public Input<string> SourceType { get; set; } = null!;

        public DatasetInitialImportDatasetConfigurationImportMetadataPathArgs()
        {
        }
        public static new DatasetInitialImportDatasetConfigurationImportMetadataPathArgs Empty => new DatasetInitialImportDatasetConfigurationImportMetadataPathArgs();
    }
}