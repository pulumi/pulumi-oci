// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Ocid of the User's Support Account.
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// (Updatable) User Token URI
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// (Updatable) The value of a X509 certificate.
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserCustomerSecretKeyArgs();
    }
}