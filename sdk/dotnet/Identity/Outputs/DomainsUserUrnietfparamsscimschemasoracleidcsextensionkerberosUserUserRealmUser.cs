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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser
    {
        /// <summary>
        /// (Updatable) Principal Name of the KerberosRealmUser associated with the Oracle Cloud Infrastructure IAM User.
        /// </summary>
        public readonly string? PrincipalName;
        /// <summary>
        /// (Updatable) Realm Name for the KerberosRealmUser associated with the Oracle Cloud Infrastructure IAM User.
        /// </summary>
        public readonly string? RealmName;
        /// <summary>
        /// (Updatable) User Token URI
        /// </summary>
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) The value of a X509 certificate.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUser(
            string? principalName,

            string? realmName,

            string? @ref,

            string value)
        {
            PrincipalName = principalName;
            RealmName = realmName;
            Ref = @ref;
            Value = value;
        }
    }
}