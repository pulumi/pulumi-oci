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
    public sealed class DomainsAppIdcsCreatedBy
    {
        /// <summary>
        /// (Updatable) Display-name of the AppRole.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Display;
        /// <summary>
        /// (Updatable) Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: global
        /// </summary>
        public readonly string? Ocid;
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
        /// (Updatable) Object Class type. Allowed values are AccountObjectClass, ManagedObjectClass.
        /// 
        /// **Added In:** 18.1.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsDefaultValue: AccountObjectClass
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Type;
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
        private DomainsAppIdcsCreatedBy(
            string? display,

            string? ocid,

            string? @ref,

            string? type,

            string value)
        {
            Display = display;
            Ocid = ocid;
            Ref = @ref;
            Type = type;
            Value = value;
        }
    }
}