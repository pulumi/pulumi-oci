// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Inputs
{

    public sealed class AgentToolToolConfigGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The connection type for Databases.
        /// </summary>
        [Input("databaseConnection")]
        public Input<Inputs.AgentToolToolConfigDatabaseConnectionGetArgs>? DatabaseConnection { get; set; }

        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        [Input("databaseSchema")]
        public Input<Inputs.AgentToolToolConfigDatabaseSchemaGetArgs>? DatabaseSchema { get; set; }

        /// <summary>
        /// (Updatable) Dialect to be used for SQL generation.
        /// </summary>
        [Input("dialect")]
        public Input<string>? Dialect { get; set; }

        /// <summary>
        /// (Updatable) Details of Function for Function calling tool.
        /// </summary>
        [Input("function")]
        public Input<Inputs.AgentToolToolConfigFunctionGetArgs>? Function { get; set; }

        /// <summary>
        /// (Updatable) Configuration to customize LLM.
        /// </summary>
        [Input("generationLlmCustomization")]
        public Input<Inputs.AgentToolToolConfigGenerationLlmCustomizationGetArgs>? GenerationLlmCustomization { get; set; }

        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        [Input("iclExamples")]
        public Input<Inputs.AgentToolToolConfigIclExamplesGetArgs>? IclExamples { get; set; }

        [Input("knowledgeBaseConfigs")]
        private InputList<Inputs.AgentToolToolConfigKnowledgeBaseConfigGetArgs>? _knowledgeBaseConfigs;

        /// <summary>
        /// (Updatable) The KnowledgeBase configurations that this RAG Tool uses
        /// </summary>
        public InputList<Inputs.AgentToolToolConfigKnowledgeBaseConfigGetArgs> KnowledgeBaseConfigs
        {
            get => _knowledgeBaseConfigs ?? (_knowledgeBaseConfigs = new InputList<Inputs.AgentToolToolConfigKnowledgeBaseConfigGetArgs>());
            set => _knowledgeBaseConfigs = value;
        }

        /// <summary>
        /// (Updatable) Size of the model.
        /// </summary>
        [Input("modelSize")]
        public Input<string>? ModelSize { get; set; }

        /// <summary>
        /// (Updatable) To enable/disable self correction.
        /// </summary>
        [Input("shouldEnableSelfCorrection")]
        public Input<bool>? ShouldEnableSelfCorrection { get; set; }

        /// <summary>
        /// (Updatable) To enable/disable SQL execution.
        /// </summary>
        [Input("shouldEnableSqlExecution")]
        public Input<bool>? ShouldEnableSqlExecution { get; set; }

        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        [Input("tableAndColumnDescription")]
        public Input<Inputs.AgentToolToolConfigTableAndColumnDescriptionGetArgs>? TableAndColumnDescription { get; set; }

        /// <summary>
        /// (Updatable) The type of the Tool config. The allowed values are:
        /// * `SQL_TOOL_CONFIG`: The config for sql Tool.
        /// * `RAG_TOOL_CONFIG`: The config for rag Tool.
        /// * FUNCTION_CALLING_TOOL_CONFIG: The config for Function calling Tool.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("toolConfigType", required: true)]
        public Input<string> ToolConfigType { get; set; } = null!;

        public AgentToolToolConfigGetArgs()
        {
        }
        public static new AgentToolToolConfigGetArgs Empty => new AgentToolToolConfigGetArgs();
    }
}
