// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppUserAssertionAttributeGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Indicates the format of the assertion attribute.
        /// 
        /// **Deprecated Since: 18.2.2**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * idcsValuePersistedInOtherAttribute: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("format")]
        public Input<string>? Format { get; set; }

        /// <summary>
        /// (Updatable) The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
        /// 
        /// **Deprecated Since: 18.2.2**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * idcsValuePersistedInOtherAttribute: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) This attribute specifies which user attribute should be used to create the value of the SAML assertion attribute. The userstore attribute can be constructed by using attributes from the Oracle Identity Cloud Service Core Users schema. &lt;br&gt;&lt;b&gt;Note&lt;/b&gt;: Attributes from extensions to the Core User schema are not supported in v1.0.
        /// 
        /// **Deprecated Since: 18.2.2**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * idcsValuePersistedInOtherAttribute: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("userStoreAttributeName", required: true)]
        public Input<string> UserStoreAttributeName { get; set; } = null!;

        public DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppUserAssertionAttributeGetArgs()
        {
        }
        public static new DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppUserAssertionAttributeGetArgs Empty => new DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppUserAssertionAttributeGetArgs();
    }
}
