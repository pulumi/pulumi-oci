// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetEntitlementsEntitlementCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A filter to return entitlements that match the given customer support identifier (CSI).
        /// </summary>
        public readonly string Csi;
        /// <summary>
        /// A filter to return only resources that match the given vendor name.
        /// </summary>
        public readonly string VendorName;

        [OutputConstructor]
        private GetEntitlementsEntitlementCollectionItemResult(
            string compartmentId,

            string csi,

            string vendorName)
        {
            CompartmentId = compartmentId;
            Csi = csi;
            VendorName = vendorName;
        }
    }
}
