// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The user's API key value.
        /// 
        /// **Added In:** 2106240046
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) The user's API key OCID.
        /// 
        /// **Added In:** 2012271618
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// (Updatable) The URI of the corresponding ApiKey resource to which the user belongs.
        /// 
        /// **Added In:** 2012271618
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
        /// (Updatable) The user's API key identifier.
        /// 
        /// **Added In:** 2012271618
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserCredentialsUserApiKeyArgs();
    }
}
