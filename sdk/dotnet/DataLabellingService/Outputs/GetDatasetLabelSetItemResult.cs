// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataLabellingService.Outputs
{

    [OutputType]
    public sealed class GetDatasetLabelSetItemResult
    {
        /// <summary>
        /// An unique name for a label within its dataset.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetDatasetLabelSetItemResult(string name)
        {
            Name = name;
        }
    }
}