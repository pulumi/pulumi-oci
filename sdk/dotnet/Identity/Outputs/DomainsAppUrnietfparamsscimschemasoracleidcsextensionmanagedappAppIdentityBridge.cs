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
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridge
    {
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
        public readonly string? Name;
        /// <summary>
        /// (Updatable) URI of the AppRole.
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
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) ID of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string? Value;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionmanagedappAppIdentityBridge(
            string? name,

            string? @ref,

            string? value)
        {
            Name = name;
            Ref = @ref;
            Value = value;
        }
    }
}