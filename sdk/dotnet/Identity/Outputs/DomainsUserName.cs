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
    public sealed class DomainsUserName
    {
        /// <summary>
        /// (Updatable) Last name
        /// </summary>
        public readonly string FamilyName;
        /// <summary>
        /// (Updatable) Full name
        /// </summary>
        public readonly string? Formatted;
        /// <summary>
        /// (Updatable) First name
        /// </summary>
        public readonly string? GivenName;
        /// <summary>
        /// (Updatable) Prefix
        /// </summary>
        public readonly string? HonorificPrefix;
        /// <summary>
        /// (Updatable) Suffix
        /// </summary>
        public readonly string? HonorificSuffix;
        /// <summary>
        /// (Updatable) Middle name
        /// </summary>
        public readonly string? MiddleName;

        [OutputConstructor]
        private DomainsUserName(
            string familyName,

            string? formatted,

            string? givenName,

            string? honorificPrefix,

            string? honorificSuffix,

            string? middleName)
        {
            FamilyName = familyName;
            Formatted = formatted;
            GivenName = givenName;
            HonorificPrefix = honorificPrefix;
            HonorificSuffix = honorificSuffix;
            MiddleName = middleName;
        }
    }
}