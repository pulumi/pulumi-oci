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
    public sealed class DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag
    {
        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tag key
        /// 
        /// **Added In:** 2011192329
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * type: string
        /// * required: true
        /// * mutability: readWrite
        /// * returned: default
        /// * idcsSearchable: true
        /// * uniqueness: none
        /// </summary>
        public readonly string Key;
        /// <summary>
        /// (Updatable) Oracle Cloud Infrastructure Tag namespace
        /// 
        /// **Added In:** 2011192329
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * type: string
        /// * required: true
        /// * mutability: readWrite
        /// * returned: default
        /// * idcsSearchable: true
        /// * uniqueness: none
        /// </summary>
        public readonly string Namespace;
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
        public readonly string Value;

        [OutputConstructor]
        private DomainsAppUrnietfparamsscimschemasoracleidcsextensionOciTagsDefinedTag(
            string key,

            string @namespace,

            string value)
        {
            Key = key;
            Namespace = @namespace;
            Value = value;
        }
    }
}