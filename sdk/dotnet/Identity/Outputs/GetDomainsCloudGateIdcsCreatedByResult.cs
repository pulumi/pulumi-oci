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
    public sealed class GetDomainsCloudGateIdcsCreatedByResult
    {
        /// <summary>
        /// The displayName of the User or App who modified this Resource
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// URI of the upstream server
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// Type of Cloud Gate
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// ID of the upstream server
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsCloudGateIdcsCreatedByResult(
            string display,

            string ocid,

            string @ref,

            string type,

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
