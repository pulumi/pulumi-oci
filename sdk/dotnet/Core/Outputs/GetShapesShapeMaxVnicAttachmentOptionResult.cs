// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetShapesShapeMaxVnicAttachmentOptionResult
    {
        /// <summary>
        /// The default number of VNIC attachments allowed per OCPU.
        /// </summary>
        public readonly double DefaultPerOcpu;
        /// <summary>
        /// The maximum allowed percentage of cores enabled.
        /// </summary>
        public readonly double Max;
        /// <summary>
        /// The minimum allowed percentage of cores enabled.
        /// </summary>
        public readonly int Min;

        [OutputConstructor]
        private GetShapesShapeMaxVnicAttachmentOptionResult(
            double defaultPerOcpu,

            double max,

            int min)
        {
            DefaultPerOcpu = defaultPerOcpu;
            Max = max;
            Min = min;
        }
    }
}