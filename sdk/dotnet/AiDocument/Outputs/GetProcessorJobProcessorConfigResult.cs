// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AiDocument.Outputs
{

    [OutputType]
    public sealed class GetProcessorJobProcessorConfigResult
    {
        /// <summary>
        /// The document type.
        /// </summary>
        public readonly string DocumentType;
        /// <summary>
        /// The types of document analysis requested.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetProcessorJobProcessorConfigFeatureResult> Features;
        /// <summary>
        /// Whether or not to generate a ZIP file containing the results.
        /// </summary>
        public readonly bool IsZipOutputEnabled;
        /// <summary>
        /// The document language, abbreviated according to the BCP 47 Language-Tag syntax.
        /// </summary>
        public readonly string Language;
        /// <summary>
        /// The type of the processor.
        /// </summary>
        public readonly string ProcessorType;

        [OutputConstructor]
        private GetProcessorJobProcessorConfigResult(
            string documentType,

            ImmutableArray<Outputs.GetProcessorJobProcessorConfigFeatureResult> features,

            bool isZipOutputEnabled,

            string language,

            string processorType)
        {
            DocumentType = documentType;
            Features = features;
            IsZipOutputEnabled = isZipOutputEnabled;
            Language = language;
            ProcessorType = processorType;
        }
    }
}