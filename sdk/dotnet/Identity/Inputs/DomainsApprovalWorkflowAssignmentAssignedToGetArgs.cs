// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsApprovalWorkflowAssignmentAssignedToGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Description
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// (Updatable) Display name of the resource for which Approval Workflow is assigned
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("display")]
        public Input<string>? Display { get; set; }

        /// <summary>
        /// Ocid of the resource for which Approval Workflow is assigned
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// Type of the resource (stripe and non-stripe) for which Approval Workflow is assigned
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
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// Identifier of the resource for which Approval Workflow is assigned
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

        public DomainsApprovalWorkflowAssignmentAssignedToGetArgs()
        {
        }
        public static new DomainsApprovalWorkflowAssignmentAssignedToGetArgs Empty => new DomainsApprovalWorkflowAssignmentAssignedToGetArgs();
    }
}
