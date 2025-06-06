// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Inputs
{

    public sealed class GetManagedInstanceGroupInstalledPackagesFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The name of the package that is installed on the managed instance group.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("regex")]
        public Input<bool>? Regex { get; set; }

        [Input("values", required: true)]
        private InputList<string>? _values;
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public GetManagedInstanceGroupInstalledPackagesFilterInputArgs()
        {
        }
        public static new GetManagedInstanceGroupInstalledPackagesFilterInputArgs Empty => new GetManagedInstanceGroupInstalledPackagesFilterInputArgs();
    }
}
