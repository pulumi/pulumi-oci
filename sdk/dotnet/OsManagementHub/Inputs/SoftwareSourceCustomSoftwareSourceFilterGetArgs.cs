// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Inputs
{

    public sealed class SoftwareSourceCustomSoftwareSourceFilterGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("moduleStreamProfileFilters")]
        private InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterGetArgs>? _moduleStreamProfileFilters;

        /// <summary>
        /// (Updatable) The list of module stream/profile filters.
        /// </summary>
        public InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterGetArgs> ModuleStreamProfileFilters
        {
            get => _moduleStreamProfileFilters ?? (_moduleStreamProfileFilters = new InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterModuleStreamProfileFilterGetArgs>());
            set => _moduleStreamProfileFilters = value;
        }

        [Input("packageFilters")]
        private InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageFilterGetArgs>? _packageFilters;

        /// <summary>
        /// (Updatable) The list of package filters.
        /// </summary>
        public InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageFilterGetArgs> PackageFilters
        {
            get => _packageFilters ?? (_packageFilters = new InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageFilterGetArgs>());
            set => _packageFilters = value;
        }

        [Input("packageGroupFilters")]
        private InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterGetArgs>? _packageGroupFilters;

        /// <summary>
        /// (Updatable) The list of group filters.
        /// </summary>
        public InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterGetArgs> PackageGroupFilters
        {
            get => _packageGroupFilters ?? (_packageGroupFilters = new InputList<Inputs.SoftwareSourceCustomSoftwareSourceFilterPackageGroupFilterGetArgs>());
            set => _packageGroupFilters = value;
        }

        public SoftwareSourceCustomSoftwareSourceFilterGetArgs()
        {
        }
        public static new SoftwareSourceCustomSoftwareSourceFilterGetArgs Empty => new SoftwareSourceCustomSoftwareSourceFilterGetArgs();
    }
}