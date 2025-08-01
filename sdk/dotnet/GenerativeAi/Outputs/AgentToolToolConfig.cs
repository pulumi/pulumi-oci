// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GenerativeAi.Outputs
{

    [OutputType]
    public sealed class AgentToolToolConfig
    {
        /// <summary>
        /// (Updatable) The connection type for Databases.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigDatabaseConnection? DatabaseConnection;
        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigDatabaseSchema? DatabaseSchema;
        /// <summary>
        /// (Updatable) Dialect to be used for SQL generation.
        /// </summary>
        public readonly string? Dialect;
        /// <summary>
        /// (Updatable) Details of Function for Function calling tool.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigFunction? Function;
        /// <summary>
        /// (Updatable) Configuration to customize LLM.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigGenerationLlmCustomization? GenerationLlmCustomization;
        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigIclExamples? IclExamples;
        /// <summary>
        /// (Updatable) The KnowledgeBase configurations that this RAG Tool uses
        /// </summary>
        public readonly ImmutableArray<Outputs.AgentToolToolConfigKnowledgeBaseConfig> KnowledgeBaseConfigs;
        /// <summary>
        /// (Updatable) Size of the model.
        /// </summary>
        public readonly string? ModelSize;
        /// <summary>
        /// (Updatable) To enable/disable self correction.
        /// </summary>
        public readonly bool? ShouldEnableSelfCorrection;
        /// <summary>
        /// (Updatable) To enable/disable SQL execution.
        /// </summary>
        public readonly bool? ShouldEnableSqlExecution;
        /// <summary>
        /// (Updatable) The input location definition.
        /// </summary>
        public readonly Outputs.AgentToolToolConfigTableAndColumnDescription? TableAndColumnDescription;
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
        public readonly string ToolConfigType;

        [OutputConstructor]
        private AgentToolToolConfig(
            Outputs.AgentToolToolConfigDatabaseConnection? databaseConnection,

            Outputs.AgentToolToolConfigDatabaseSchema? databaseSchema,

            string? dialect,

            Outputs.AgentToolToolConfigFunction? function,

            Outputs.AgentToolToolConfigGenerationLlmCustomization? generationLlmCustomization,

            Outputs.AgentToolToolConfigIclExamples? iclExamples,

            ImmutableArray<Outputs.AgentToolToolConfigKnowledgeBaseConfig> knowledgeBaseConfigs,

            string? modelSize,

            bool? shouldEnableSelfCorrection,

            bool? shouldEnableSqlExecution,

            Outputs.AgentToolToolConfigTableAndColumnDescription? tableAndColumnDescription,

            string toolConfigType)
        {
            DatabaseConnection = databaseConnection;
            DatabaseSchema = databaseSchema;
            Dialect = dialect;
            Function = function;
            GenerationLlmCustomization = generationLlmCustomization;
            IclExamples = iclExamples;
            KnowledgeBaseConfigs = knowledgeBaseConfigs;
            ModelSize = modelSize;
            ShouldEnableSelfCorrection = shouldEnableSelfCorrection;
            ShouldEnableSqlExecution = shouldEnableSqlExecution;
            TableAndColumnDescription = tableAndColumnDescription;
            ToolConfigType = toolConfigType;
        }
    }
}
