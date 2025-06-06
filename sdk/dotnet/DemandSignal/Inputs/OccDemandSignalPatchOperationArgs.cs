// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DemandSignal.Inputs
{

    public sealed class OccDemandSignalPatchOperationArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("from", required: true)]
        public Input<string> From { get; set; } = null!;

        /// <summary>
        /// (Updatable) The operation can be one of these values: `INSERT`, `INSERT_MULTIPLE`, `MERGE`, `MOVE`, `PROHIBIT`, `REMOVE`, `REPLACE`, `REQUIRE`
        /// </summary>
        [Input("operation", required: true)]
        public Input<string> Operation { get; set; } = null!;

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("position")]
        public Input<string>? Position { get; set; }

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("selectedItem")]
        public Input<string>? SelectedItem { get; set; }

        /// <summary>
        /// (Updatable)
        /// </summary>
        [Input("selection", required: true)]
        public Input<string> Selection { get; set; } = null!;

        [Input("value", required: true)]
        private InputMap<string>? _value;

        /// <summary>
        /// (Updatable)
        /// </summary>
        public InputMap<string> Value
        {
            get => _value ?? (_value = new InputMap<string>());
            set => _value = value;
        }

        public OccDemandSignalPatchOperationArgs()
        {
        }
        public static new OccDemandSignalPatchOperationArgs Empty => new OccDemandSignalPatchOperationArgs();
    }
}
