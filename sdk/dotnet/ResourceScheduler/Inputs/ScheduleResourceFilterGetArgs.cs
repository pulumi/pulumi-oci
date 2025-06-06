// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceScheduler.Inputs
{

    public sealed class ScheduleResourceFilterGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) This is the resource attribute on which the threshold is defined. We support 5 different types of attributes: `DEFINED_TAGS`, `COMPARTMENT_ID`, `TIME_CREATED`, `LIFECYCLE_STATE` and `RESOURCE_TYPE`.
        /// </summary>
        [Input("attribute", required: true)]
        public Input<string> Attribute { get; set; } = null!;

        /// <summary>
        /// This is the condition for the filter in comparison to its creation time.
        /// </summary>
        [Input("condition")]
        public Input<string>? Condition { get; set; }

        /// <summary>
        /// This sets whether to include child compartments.
        /// </summary>
        [Input("shouldIncludeChildCompartments")]
        public Input<bool>? ShouldIncludeChildCompartments { get; set; }

        [Input("values")]
        private InputList<Inputs.ScheduleResourceFilterValueGetArgs>? _values;

        /// <summary>
        /// (Updatable) This is a collection of resource filter values, different types of filter has different value format, see below:
        /// * When `attribute="DEFINED_TAGS"`:
        /// </summary>
        public InputList<Inputs.ScheduleResourceFilterValueGetArgs> Values
        {
            get => _values ?? (_values = new InputList<Inputs.ScheduleResourceFilterValueGetArgs>());
            set => _values = value;
        }

        public ScheduleResourceFilterGetArgs()
        {
        }
        public static new ScheduleResourceFilterGetArgs Empty => new ScheduleResourceFilterGetArgs();
    }
}
