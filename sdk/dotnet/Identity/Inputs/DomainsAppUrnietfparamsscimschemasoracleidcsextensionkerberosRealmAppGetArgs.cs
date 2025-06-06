// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmAppGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type of salt that the system will use to encrypt Kerberos-specific artifacts of this App unless another type of salt is specified.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("defaultEncryptionSaltType")]
        public Input<string>? DefaultEncryptionSaltType { get; set; }

        /// <summary>
        /// (Updatable) The primary key that the system should use to encrypt artifacts that are specific to this Kerberos realm -- for example, to encrypt the Principal Key in each KerberosRealmUser.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * idcsSensitive: none
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("masterKey")]
        public Input<string>? MasterKey { get; set; }

        /// <summary>
        /// (Updatable) Max Renewable Age in seconds
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("maxRenewableAge")]
        public Input<int>? MaxRenewableAge { get; set; }

        /// <summary>
        /// (Updatable) Max Ticket Life in seconds
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("maxTicketLife")]
        public Input<int>? MaxTicketLife { get; set; }

        /// <summary>
        /// (Updatable) The name of the Kerberos Realm that this App uses for authentication.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("realmName")]
        public Input<string>? RealmName { get; set; }

        [Input("supportedEncryptionSaltTypes")]
        private InputList<string>? _supportedEncryptionSaltTypes;

        /// <summary>
        /// (Updatable) The types of salt that are available for the system to use when encrypting Kerberos-specific artifacts for this App.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: true
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public InputList<string> SupportedEncryptionSaltTypes
        {
            get => _supportedEncryptionSaltTypes ?? (_supportedEncryptionSaltTypes = new InputList<string>());
            set => _supportedEncryptionSaltTypes = value;
        }

        /// <summary>
        /// (Updatable) Ticket Flags
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("ticketFlags")]
        public Input<int>? TicketFlags { get; set; }

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmAppGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmAppGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionkerberosRealmAppGetArgs();
    }
}
