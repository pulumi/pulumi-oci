// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserAddress
    {
        /// <summary>
        /// (Updatable) The country name component.
        /// </summary>
        public readonly string? Country;
        /// <summary>
        /// (Updatable) Full name
        /// </summary>
        public readonly string? Formatted;
        /// <summary>
        /// (Updatable) The city or locality component.
        /// </summary>
        public readonly string? Locality;
        /// <summary>
        /// (Updatable) The zipcode or postal code component.
        /// </summary>
        public readonly string? PostalCode;
        /// <summary>
        /// (Updatable) A Boolean value indicating the 'primary' or preferred attribute value for this attribute. The primary attribute value 'true' MUST appear no more than once.
        /// </summary>
        public readonly bool? Primary;
        /// <summary>
        /// (Updatable) The state or region component.
        /// </summary>
        public readonly string? Region;
        /// <summary>
        /// (Updatable) The full street address component, which may include house number, street name, PO BOX, and multi-line extended street address information. This attribute MAY contain newlines.
        /// </summary>
        public readonly string? StreetAddress;
        /// <summary>
        /// (Updatable) A label indicating the attribute's function.
        /// </summary>
        public readonly string Type;

        [OutputConstructor]
        private DomainsUserAddress(
            string? country,

            string? formatted,

            string? locality,

            string? postalCode,

            bool? primary,

            string? region,

            string? streetAddress,

            string type)
        {
            Country = country;
            Formatted = formatted;
            Locality = locality;
            PostalCode = postalCode;
            Primary = primary;
            Region = region;
            StreetAddress = streetAddress;
            Type = type;
        }
    }
}