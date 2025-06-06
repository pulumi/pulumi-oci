// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsSelfRegistrationProfileUserAttributeGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) If this attribute can be deleted
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        [Input("deletable")]
        public Input<bool>? Deletable { get; set; }

        /// <summary>
        /// (Updatable) **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none Fully Qualified Attribute Name
        /// </summary>
        [Input("fullyQualifiedAttributeName")]
        public Input<string>? FullyQualifiedAttributeName { get; set; }

        /// <summary>
        /// (Updatable) Metadata of the user attribute
        /// 
        /// **Added In:** 18.1.6
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("metadata")]
        public Input<string>? Metadata { get; set; }

        /// <summary>
        /// (Updatable) **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none Sequence Number for the attribute
        /// </summary>
        [Input("seqNumber", required: true)]
        public Input<int> SeqNumber { get; set; } = null!;

        /// <summary>
        /// (Updatable) name of the attribute
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsSelfRegistrationProfileUserAttributeGetArgs()
        {
        }
        public static new DomainsSelfRegistrationProfileUserAttributeGetArgs Empty => new DomainsSelfRegistrationProfileUserAttributeGetArgs();
    }
}
