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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag
    {
        /// <summary>
        /// (Updatable) The value of of the User's api key.
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tag namespace
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// (Updatable) The value of a X509 certificate.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag(
            string key,

            string @namespace,

            string value)
        {
            Key = key;
            Namespace = @namespace;
            Value = value;
        }
    }
}