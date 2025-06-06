// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsApprovalWorkflowAssignmentApprovalWorkflowGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Display name of the approval workflow
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
        /// Unique Oracle Cloud Infrastructure Identifier of the approval workflow
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("ocid")]
        public Input<string>? Ocid { get; set; }

        /// <summary>
        /// (Updatable) URI of the approval workflow
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        [Input("ref")]
        public Input<string>? Ref { get; set; }

        /// <summary>
        /// Indicates type of the entity that is associated with this assignment (for ARM validation)
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * idcsDefaultValue: ApprovalWorkflow
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: request
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// Identifier of the approval workflow
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

        public DomainsApprovalWorkflowAssignmentApprovalWorkflowGetArgs()
        {
        }
        public static new DomainsApprovalWorkflowAssignmentApprovalWorkflowGetArgs Empty => new DomainsApprovalWorkflowAssignmentApprovalWorkflowGetArgs();
    }
}
