// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics.Inputs
{

    public sealed class NamespaceScheduledTaskActionTemplateDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The template Id of a particular template.  Should not be provided when a saved search ID is present.
        /// </summary>
        [Input("templateId")]
        public Input<string>? TemplateId { get; set; }

        [Input("templateParams")]
        private InputList<Inputs.NamespaceScheduledTaskActionTemplateDetailsTemplateParamGetArgs>? _templateParams;

        /// <summary>
        /// To store macro params.
        /// </summary>
        public InputList<Inputs.NamespaceScheduledTaskActionTemplateDetailsTemplateParamGetArgs> TemplateParams
        {
            get => _templateParams ?? (_templateParams = new InputList<Inputs.NamespaceScheduledTaskActionTemplateDetailsTemplateParamGetArgs>());
            set => _templateParams = value;
        }

        public NamespaceScheduledTaskActionTemplateDetailsGetArgs()
        {
        }
        public static new NamespaceScheduledTaskActionTemplateDetailsGetArgs Empty => new NamespaceScheduledTaskActionTemplateDetailsGetArgs();
    }
}
