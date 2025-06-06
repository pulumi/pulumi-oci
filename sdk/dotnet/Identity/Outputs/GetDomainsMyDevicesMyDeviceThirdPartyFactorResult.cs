// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsMyDevicesMyDeviceThirdPartyFactorResult
    {
        /// <summary>
        /// The URI that corresponds to the member Resource of this device
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// Type of the third party authentication factor
        /// </summary>
        public readonly string ThirdPartyFactorType;
        /// <summary>
        /// The vendor name of the third party factor
        /// </summary>
        public readonly string ThirdPartyVendorName;
        /// <summary>
        /// The identifier of the user
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsMyDevicesMyDeviceThirdPartyFactorResult(
            string @ref,

            string thirdPartyFactorType,

            string thirdPartyVendorName,

            string value)
        {
            Ref = @ref;
            ThirdPartyFactorType = thirdPartyFactorType;
            ThirdPartyVendorName = thirdPartyVendorName;
            Value = value;
        }
    }
}
