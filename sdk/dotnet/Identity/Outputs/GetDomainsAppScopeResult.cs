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
    public sealed class GetDomainsAppScopeResult
    {
        /// <summary>
        /// The description of the AppRole.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Display name of the flatfile bundle configuration property. This attribute maps to \"displayName\" attribute in \"ConfigurationProperty\" in ICF.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The fully qualified value of this scope within this App. A fully qualified scope combines the 'value' of each scope with the value of 'audience'. Each value of 'fqs' must be unique across the system. Used only when this App acts as an OAuth Resource.
        /// </summary>
        public readonly string Fqs;
        /// <summary>
        /// If true, indicates that this value must be protected.
        /// </summary>
        public readonly bool ReadOnly;
        /// <summary>
        /// If true, indicates that a user must provide consent to access this scope. Note: Used only when this App acts as an OAuth Resource.
        /// </summary>
        public readonly bool RequiresConsent;
        /// <summary>
        /// ID of the AppRole.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsAppScopeResult(
            string description,

            string displayName,

            string fqs,

            bool readOnly,

            bool requiresConsent,

            string value)
        {
            Description = description;
            DisplayName = displayName;
            Fqs = fqs;
            ReadOnly = readOnly;
            RequiresConsent = requiresConsent;
            Value = value;
        }
    }
}