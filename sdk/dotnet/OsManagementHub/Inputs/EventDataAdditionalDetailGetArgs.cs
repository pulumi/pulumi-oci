// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Inputs
{

    public sealed class EventDataAdditionalDetailGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("exploitCves")]
        private InputList<string>? _exploitCves;

        /// <summary>
        /// List of CVEs in the exploit.
        /// </summary>
        public InputList<string> ExploitCves
        {
            get => _exploitCves ?? (_exploitCves = new InputList<string>());
            set => _exploitCves = value;
        }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource that triggered the event, such as scheduled job id.
        /// </summary>
        [Input("initiatorId")]
        public Input<string>? InitiatorId { get; set; }

        [Input("vmcores")]
        private InputList<Inputs.EventDataAdditionalDetailVmcoreGetArgs>? _vmcores;

        /// <summary>
        /// Kernel event vmcore details
        /// </summary>
        public InputList<Inputs.EventDataAdditionalDetailVmcoreGetArgs> Vmcores
        {
            get => _vmcores ?? (_vmcores = new InputList<Inputs.EventDataAdditionalDetailVmcoreGetArgs>());
            set => _vmcores = value;
        }

        [Input("workRequestIds")]
        private InputList<string>? _workRequestIds;

        /// <summary>
        /// List of all work request [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) associated with the event.
        /// </summary>
        public InputList<string> WorkRequestIds
        {
            get => _workRequestIds ?? (_workRequestIds = new InputList<string>());
            set => _workRequestIds = value;
        }

        public EventDataAdditionalDetailGetArgs()
        {
        }
        public static new EventDataAdditionalDetailGetArgs Empty => new EventDataAdditionalDetailGetArgs();
    }
}
