// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Marketplace.Inputs
{

    public sealed class PublicationPackageDetailsArgs : global::Pulumi.ResourceArgs
    {
        [Input("eulas", required: true)]
        private InputList<Inputs.PublicationPackageDetailsEulaArgs>? _eulas;

        /// <summary>
        /// The end user license agreeement (EULA) that consumers of this listing must accept.
        /// </summary>
        public InputList<Inputs.PublicationPackageDetailsEulaArgs> Eulas
        {
            get => _eulas ?? (_eulas = new InputList<Inputs.PublicationPackageDetailsEulaArgs>());
            set => _eulas = value;
        }

        /// <summary>
        /// The unique identifier for the base image of the publication.
        /// </summary>
        [Input("imageId")]
        public Input<string>? ImageId { get; set; }

        /// <summary>
        /// The operating system used by the listing.
        /// </summary>
        [Input("operatingSystem", required: true)]
        public Input<Inputs.PublicationPackageDetailsOperatingSystemArgs> OperatingSystem { get; set; } = null!;

        /// <summary>
        /// The package's type.
        /// </summary>
        [Input("packageType", required: true)]
        public Input<string> PackageType { get; set; } = null!;

        /// <summary>
        /// The package version.
        /// </summary>
        [Input("packageVersion", required: true)]
        public Input<string> PackageVersion { get; set; } = null!;

        public PublicationPackageDetailsArgs()
        {
        }
        public static new PublicationPackageDetailsArgs Empty => new PublicationPackageDetailsArgs();
    }
}