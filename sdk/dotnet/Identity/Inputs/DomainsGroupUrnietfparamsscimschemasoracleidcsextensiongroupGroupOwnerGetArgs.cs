// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Owner display name
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
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// (Updatable) The URI that corresponds to the owning Resource of this Group
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
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
        /// (Updatable) Indicates the type of resource--for example, User or Group
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsDefaultValue: User
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// (Updatable) ID of the owner of this Group
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerGetArgs()
        {
        }
        public static new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerGetArgs Empty => new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerGetArgs();
    }
}
