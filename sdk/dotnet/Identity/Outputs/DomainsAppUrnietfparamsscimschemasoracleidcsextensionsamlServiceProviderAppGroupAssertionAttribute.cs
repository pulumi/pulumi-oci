// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppGroupAssertionAttribute
    {
        /// <summary>
        /// (Updatable) Indicates the filter types that are supported for the Group assertion attributes.
        /// 
        /// **Deprecated Since: 18.2.2**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * idcsValuePersistedInOtherAttribute: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Condition;
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
        public readonly string? Format;
        /// <summary>
        /// (Updatable) Indicates the group name that are supported for the group assertion attributes.
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
        public readonly string? GroupName;
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
        public readonly string Name;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionsamlServiceProviderAppGroupAssertionAttribute(
            string? condition,

            string? format,

            string? groupName,

            string name)
        {
            Condition = condition;
            Format = format;
            GroupName = groupName;
            Name = name;
        }
    }
}
