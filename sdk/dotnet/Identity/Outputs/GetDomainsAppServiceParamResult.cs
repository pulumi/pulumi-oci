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
    public sealed class GetDomainsAppServiceParamResult
    {
        /// <summary>
        /// The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// ID of the AppRole.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsAppServiceParamResult(
            string name,

            string value)
        {
            Name = name;
            Value = value;
        }
    }
}
