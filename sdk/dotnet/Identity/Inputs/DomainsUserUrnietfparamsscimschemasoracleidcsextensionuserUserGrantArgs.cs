// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The ID of the App in this Grant.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("appId")]
        public Input<string>? AppId { get; set; }

        /// <summary>
        /// (Updatable) Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with 'ADMINISTRATOR':
        /// * 'ADMINISTRATOR_TO_USER' is for a direct grant to a specific User.
        /// * 'ADMINISTRATOR_TO_GROUP' is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
        /// * 'ADMINISTRATOR_TO_APP' is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("grantMechanism")]
        public Input<string>? GrantMechanism { get; set; }

        /// <summary>
        /// (Updatable) Grantor identifier
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("grantorId")]
        public Input<string>? GrantorId { get; set; }

        /// <summary>
        /// (Updatable) The URI of this Grant to this User.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// (Updatable) The ID of this Grant to this User.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserGrantArgs();
    }
}
