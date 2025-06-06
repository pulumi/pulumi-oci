// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CapacityManagement.Inputs
{

    public sealed class OccCapacityRequestDetailAssociatedOccHandoverResourceBlockListGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The total quantity of the resource that was made available to the customer as part of this resource block
        /// </summary>
        [Input("handoverQuantity")]
        public Input<string>? HandoverQuantity { get; set; }

        /// <summary>
        /// The OCID of the handed over resource block.
        /// </summary>
        [Input("occHandoverResourceBlockId")]
        public Input<string>? OccHandoverResourceBlockId { get; set; }

        public OccCapacityRequestDetailAssociatedOccHandoverResourceBlockListGetArgs()
        {
        }
        public static new OccCapacityRequestDetailAssociatedOccHandoverResourceBlockListGetArgs Empty => new OccCapacityRequestDetailAssociatedOccHandoverResourceBlockListGetArgs();
    }
}
