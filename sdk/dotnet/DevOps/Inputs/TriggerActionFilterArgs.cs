// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Inputs
{

    public sealed class TriggerActionFilterArgs : Pulumi.ResourceArgs
    {
        [Input("events")]
        private InputList<string>? _events;

        /// <summary>
        /// (Updatable) The events, for example, PUSH, PULL_REQUEST_MERGE.
        /// </summary>
        public InputList<string> Events
        {
            get => _events ?? (_events = new InputList<string>());
            set => _events = value;
        }

        /// <summary>
        /// (Updatable) Attributes to filter DevOps code repository events.
        /// </summary>
        [Input("include")]
        public Input<Inputs.TriggerActionFilterIncludeArgs>? Include { get; set; }

        /// <summary>
        /// (Updatable) Source of the trigger. Allowed values are, GITHUB and GITLAB.
        /// </summary>
        [Input("triggerSource", required: true)]
        public Input<string> TriggerSource { get; set; } = null!;

        public TriggerActionFilterArgs()
        {
        }
    }
}
