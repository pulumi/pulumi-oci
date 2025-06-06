// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserArgs : global::Pulumi.ResourceArgs
    {
        [Input("realmUsers")]
        private InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUserArgs>? _realmUsers;

        /// <summary>
        /// (Updatable) A list of kerberos realm users for an Oracle Identity Cloud Service User
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCompositeKey: [value]
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        public InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUserArgs> RealmUsers
        {
            get => _realmUsers ?? (_realmUsers = new InputList<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUserArgs>());
            set => _realmUsers = value;
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserArgs();
    }
}
