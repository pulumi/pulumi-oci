// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class GetAssetComputeNvdimmControllerResult
    {
        /// <summary>
        /// Bus number.
        /// </summary>
        public readonly int BusNumber;
        /// <summary>
        /// Provides a label and summary information for the device.
        /// </summary>
        public readonly string Label;

        [OutputConstructor]
        private GetAssetComputeNvdimmControllerResult(
            int busNumber,

            string label)
        {
            BusNumber = busNumber;
            Label = label;
        }
    }
}