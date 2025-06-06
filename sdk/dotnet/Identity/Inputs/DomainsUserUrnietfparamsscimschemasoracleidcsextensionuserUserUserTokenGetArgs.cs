// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) User Token URI
        /// 
        /// **Added In:** 18.4.2
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
        /// (Updatable) User Token identifier
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserUserTokenGetArgs();
    }
}
