// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentKnowledgeBaseIndexConfigDatabaseFunctionGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The name of the Database function.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public AgentKnowledgeBaseIndexConfigDatabaseFunctionGetArgs()
        {
        }
        public static new AgentKnowledgeBaseIndexConfigDatabaseFunctionGetArgs Empty => new AgentKnowledgeBaseIndexConfigDatabaseFunctionGetArgs();
    }
}
