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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier
    {
        /// <summary>
        /// (Updatable) A label indicating the attribute's function.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable) The value of a X509 certificate.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier(
            string type,

            string value)
        {
            Type = type;
            Value = value;
        }
    }
}