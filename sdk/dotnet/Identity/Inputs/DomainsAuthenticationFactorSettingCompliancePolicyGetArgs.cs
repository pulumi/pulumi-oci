// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsAuthenticationFactorSettingCompliancePolicyGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The action to be taken if the value of the attribute is not as expected
        /// </summary>
        [Input("action", required: true)]
        public Input<string> Action { get; set; } = null!;

        /// <summary>
        /// (Updatable) The name of the attribute being evaluated
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        /// <summary>
        /// (Updatable) Value of the tag.
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public DomainsAuthenticationFactorSettingCompliancePolicyGetArgs()
        {
        }
        public static new DomainsAuthenticationFactorSettingCompliancePolicyGetArgs Empty => new DomainsAuthenticationFactorSettingCompliancePolicyGetArgs();
    }
}