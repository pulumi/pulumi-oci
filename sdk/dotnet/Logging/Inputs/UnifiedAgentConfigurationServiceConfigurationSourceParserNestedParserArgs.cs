// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Logging.Inputs
{

    public sealed class UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParserArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) Specify the time field for the event time. If the event doesn't have this field, the current time is used.
        /// </summary>
        [Input("fieldTimeKey")]
        public Input<string>? FieldTimeKey { get; set; }

        /// <summary>
        /// (Updatable) If true, keep time field in the record.
        /// </summary>
        [Input("isKeepTimeKey")]
        public Input<bool>? IsKeepTimeKey { get; set; }

        /// <summary>
        /// (Updatable) Process time value using the specified format.
        /// </summary>
        [Input("timeFormat")]
        public Input<string>? TimeFormat { get; set; }

        /// <summary>
        /// (Updatable) Time type of JSON parser.
        /// </summary>
        [Input("timeType")]
        public Input<string>? TimeType { get; set; }

        public UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParserArgs()
        {
        }
        public static new UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParserArgs Empty => new UnifiedAgentConfigurationServiceConfigurationSourceParserNestedParserArgs();
    }
}