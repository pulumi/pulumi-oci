// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm.Inputs
{

    public sealed class RemediationRunStageGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Information about the current step within the given stage.
        /// </summary>
        [Input("summary")]
        public Input<string>? Summary { get; set; }

        /// <summary>
        /// The creation date and time of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time of the finish of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        [Input("timeFinished")]
        public Input<string>? TimeFinished { get; set; }

        /// <summary>
        /// The date and time of the start of the remediation run (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        [Input("timeStarted")]
        public Input<string>? TimeStarted { get; set; }

        /// <summary>
        /// The type of stage.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public RemediationRunStageGetArgs()
        {
        }
        public static new RemediationRunStageGetArgs Empty => new RemediationRunStageGetArgs();
    }
}