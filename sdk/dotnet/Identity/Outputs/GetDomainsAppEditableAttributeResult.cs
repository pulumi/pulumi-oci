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
    public sealed class GetDomainsAppEditableAttributeResult
    {
        /// <summary>
        /// The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetDomainsAppEditableAttributeResult(string name)
        {
            Name = name;
        }
    }
}