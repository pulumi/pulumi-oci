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
    public sealed class DomainsIdentityProviderIdcsCreatedBy
    {
        /// <summary>
        /// (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
        /// </summary>
        public readonly string? Display;
        /// <summary>
        /// (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string? Ocid;
        /// <summary>
        /// (Updatable) Group URI
        /// </summary>
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) Identity Provider Type
        /// </summary>
        public readonly string? Type;
        /// <summary>
        /// (Updatable) Value of the tag.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsIdentityProviderIdcsCreatedBy(
            string? display,

            string? ocid,

            string? @ref,

            string? type,

            string value)
        {
            Display = display;
            Ocid = ocid;
            Ref = @ref;
            Type = type;
            Value = value;
        }
    }
}