// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Inputs
{

    public sealed class AddonConfigurationGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) configuration key name
        /// </summary>
        [Input("key")]
        public Input<string>? Key { get; set; }

        /// <summary>
        /// (Updatable) configuration value name
        /// </summary>
        [Input("value")]
        public Input<string>? Value { get; set; }

        public AddonConfigurationGetArgs()
        {
        }
        public static new AddonConfigurationGetArgs Empty => new AddonConfigurationGetArgs();
    }
}