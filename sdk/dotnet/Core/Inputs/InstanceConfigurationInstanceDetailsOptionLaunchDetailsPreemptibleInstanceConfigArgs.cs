// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Inputs
{

    public sealed class InstanceConfigurationInstanceDetailsOptionLaunchDetailsPreemptibleInstanceConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The action to run when the preemptible instance is interrupted for eviction.
        /// </summary>
        [Input("preemptionAction")]
        public Input<Inputs.InstanceConfigurationInstanceDetailsOptionLaunchDetailsPreemptibleInstanceConfigPreemptionActionArgs>? PreemptionAction { get; set; }

        public InstanceConfigurationInstanceDetailsOptionLaunchDetailsPreemptibleInstanceConfigArgs()
        {
        }
        public static new InstanceConfigurationInstanceDetailsOptionLaunchDetailsPreemptibleInstanceConfigArgs Empty => new InstanceConfigurationInstanceDetailsOptionLaunchDetailsPreemptibleInstanceConfigArgs();
    }
}