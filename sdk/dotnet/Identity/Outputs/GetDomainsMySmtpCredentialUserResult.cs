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
    public sealed class GetDomainsMySmtpCredentialUserResult
    {
        /// <summary>
        /// User display name
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// User name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// User's ocid
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// The URI that corresponds to the user linked to this credential
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// User's id
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsMySmtpCredentialUserResult(
            string display,

            string name,

            string ocid,

            string @ref,

            string value)
        {
            Display = display;
            Name = name;
            Ocid = ocid;
            Ref = @ref;
            Value = value;
        }
    }
}
