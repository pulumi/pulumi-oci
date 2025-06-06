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
    public sealed class DomainsAppRoleApp
    {
        /// <summary>
        /// (Updatable) App display name
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Display;
        /// <summary>
        /// (Updatable) Application name
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) App URI
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
        /// (Updatable) The serviceInstanceIdentifier of the App that defines this AppRole. This value will match the opcServiceInstanceGUID of any service-instance that the App represents.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? ServiceInstanceIdentifier;
        /// <summary>
        /// App identifier
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: immutable
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsAppRoleApp(
            string? display,

            string? name,

            string? @ref,

            string? serviceInstanceIdentifier,

            string value)
        {
            Display = display;
            Name = name;
            Ref = @ref;
            ServiceInstanceIdentifier = serviceInstanceIdentifier;
            Value = value;
        }
    }
}
