// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class AssetComputeNvdimm
    {
        /// <summary>
        /// (Updatable) Controller key.
        /// </summary>
        public readonly int? ControllerKey;
        /// <summary>
        /// (Updatable) Provides a label and summary information for the device.
        /// </summary>
        public readonly string? Label;
        /// <summary>
        /// (Updatable) The unit number of NVDIMM.
        /// </summary>
        public readonly int? UnitNumber;

        [OutputConstructor]
        private AssetComputeNvdimm(
            int? controllerKey,

            string? label,

            int? unitNumber)
        {
            ControllerKey = controllerKey;
            Label = label;
            UnitNumber = unitNumber;
        }
    }
}
