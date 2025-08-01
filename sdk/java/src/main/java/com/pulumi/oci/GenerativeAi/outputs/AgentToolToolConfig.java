// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigDatabaseConnection;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigDatabaseSchema;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigFunction;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigGenerationLlmCustomization;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigIclExamples;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigKnowledgeBaseConfig;
import com.pulumi.oci.GenerativeAi.outputs.AgentToolToolConfigTableAndColumnDescription;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AgentToolToolConfig {
    /**
     * @return (Updatable) The connection type for Databases.
     * 
     */
    private @Nullable AgentToolToolConfigDatabaseConnection databaseConnection;
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    private @Nullable AgentToolToolConfigDatabaseSchema databaseSchema;
    /**
     * @return (Updatable) Dialect to be used for SQL generation.
     * 
     */
    private @Nullable String dialect;
    /**
     * @return (Updatable) Details of Function for Function calling tool.
     * 
     */
    private @Nullable AgentToolToolConfigFunction function;
    /**
     * @return (Updatable) Configuration to customize LLM.
     * 
     */
    private @Nullable AgentToolToolConfigGenerationLlmCustomization generationLlmCustomization;
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    private @Nullable AgentToolToolConfigIclExamples iclExamples;
    /**
     * @return (Updatable) The KnowledgeBase configurations that this RAG Tool uses
     * 
     */
    private @Nullable List<AgentToolToolConfigKnowledgeBaseConfig> knowledgeBaseConfigs;
    /**
     * @return (Updatable) Size of the model.
     * 
     */
    private @Nullable String modelSize;
    /**
     * @return (Updatable) To enable/disable self correction.
     * 
     */
    private @Nullable Boolean shouldEnableSelfCorrection;
    /**
     * @return (Updatable) To enable/disable SQL execution.
     * 
     */
    private @Nullable Boolean shouldEnableSqlExecution;
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    private @Nullable AgentToolToolConfigTableAndColumnDescription tableAndColumnDescription;
    /**
     * @return (Updatable) The type of the Tool config. The allowed values are:
     * * `SQL_TOOL_CONFIG`: The config for sql Tool.
     * * `RAG_TOOL_CONFIG`: The config for rag Tool.
     * * FUNCTION_CALLING_TOOL_CONFIG: The config for Function calling Tool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String toolConfigType;

    private AgentToolToolConfig() {}
    /**
     * @return (Updatable) The connection type for Databases.
     * 
     */
    public Optional<AgentToolToolConfigDatabaseConnection> databaseConnection() {
        return Optional.ofNullable(this.databaseConnection);
    }
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    public Optional<AgentToolToolConfigDatabaseSchema> databaseSchema() {
        return Optional.ofNullable(this.databaseSchema);
    }
    /**
     * @return (Updatable) Dialect to be used for SQL generation.
     * 
     */
    public Optional<String> dialect() {
        return Optional.ofNullable(this.dialect);
    }
    /**
     * @return (Updatable) Details of Function for Function calling tool.
     * 
     */
    public Optional<AgentToolToolConfigFunction> function() {
        return Optional.ofNullable(this.function);
    }
    /**
     * @return (Updatable) Configuration to customize LLM.
     * 
     */
    public Optional<AgentToolToolConfigGenerationLlmCustomization> generationLlmCustomization() {
        return Optional.ofNullable(this.generationLlmCustomization);
    }
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    public Optional<AgentToolToolConfigIclExamples> iclExamples() {
        return Optional.ofNullable(this.iclExamples);
    }
    /**
     * @return (Updatable) The KnowledgeBase configurations that this RAG Tool uses
     * 
     */
    public List<AgentToolToolConfigKnowledgeBaseConfig> knowledgeBaseConfigs() {
        return this.knowledgeBaseConfigs == null ? List.of() : this.knowledgeBaseConfigs;
    }
    /**
     * @return (Updatable) Size of the model.
     * 
     */
    public Optional<String> modelSize() {
        return Optional.ofNullable(this.modelSize);
    }
    /**
     * @return (Updatable) To enable/disable self correction.
     * 
     */
    public Optional<Boolean> shouldEnableSelfCorrection() {
        return Optional.ofNullable(this.shouldEnableSelfCorrection);
    }
    /**
     * @return (Updatable) To enable/disable SQL execution.
     * 
     */
    public Optional<Boolean> shouldEnableSqlExecution() {
        return Optional.ofNullable(this.shouldEnableSqlExecution);
    }
    /**
     * @return (Updatable) The input location definition.
     * 
     */
    public Optional<AgentToolToolConfigTableAndColumnDescription> tableAndColumnDescription() {
        return Optional.ofNullable(this.tableAndColumnDescription);
    }
    /**
     * @return (Updatable) The type of the Tool config. The allowed values are:
     * * `SQL_TOOL_CONFIG`: The config for sql Tool.
     * * `RAG_TOOL_CONFIG`: The config for rag Tool.
     * * FUNCTION_CALLING_TOOL_CONFIG: The config for Function calling Tool.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String toolConfigType() {
        return this.toolConfigType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AgentToolToolConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable AgentToolToolConfigDatabaseConnection databaseConnection;
        private @Nullable AgentToolToolConfigDatabaseSchema databaseSchema;
        private @Nullable String dialect;
        private @Nullable AgentToolToolConfigFunction function;
        private @Nullable AgentToolToolConfigGenerationLlmCustomization generationLlmCustomization;
        private @Nullable AgentToolToolConfigIclExamples iclExamples;
        private @Nullable List<AgentToolToolConfigKnowledgeBaseConfig> knowledgeBaseConfigs;
        private @Nullable String modelSize;
        private @Nullable Boolean shouldEnableSelfCorrection;
        private @Nullable Boolean shouldEnableSqlExecution;
        private @Nullable AgentToolToolConfigTableAndColumnDescription tableAndColumnDescription;
        private String toolConfigType;
        public Builder() {}
        public Builder(AgentToolToolConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.databaseConnection = defaults.databaseConnection;
    	      this.databaseSchema = defaults.databaseSchema;
    	      this.dialect = defaults.dialect;
    	      this.function = defaults.function;
    	      this.generationLlmCustomization = defaults.generationLlmCustomization;
    	      this.iclExamples = defaults.iclExamples;
    	      this.knowledgeBaseConfigs = defaults.knowledgeBaseConfigs;
    	      this.modelSize = defaults.modelSize;
    	      this.shouldEnableSelfCorrection = defaults.shouldEnableSelfCorrection;
    	      this.shouldEnableSqlExecution = defaults.shouldEnableSqlExecution;
    	      this.tableAndColumnDescription = defaults.tableAndColumnDescription;
    	      this.toolConfigType = defaults.toolConfigType;
        }

        @CustomType.Setter
        public Builder databaseConnection(@Nullable AgentToolToolConfigDatabaseConnection databaseConnection) {

            this.databaseConnection = databaseConnection;
            return this;
        }
        @CustomType.Setter
        public Builder databaseSchema(@Nullable AgentToolToolConfigDatabaseSchema databaseSchema) {

            this.databaseSchema = databaseSchema;
            return this;
        }
        @CustomType.Setter
        public Builder dialect(@Nullable String dialect) {

            this.dialect = dialect;
            return this;
        }
        @CustomType.Setter
        public Builder function(@Nullable AgentToolToolConfigFunction function) {

            this.function = function;
            return this;
        }
        @CustomType.Setter
        public Builder generationLlmCustomization(@Nullable AgentToolToolConfigGenerationLlmCustomization generationLlmCustomization) {

            this.generationLlmCustomization = generationLlmCustomization;
            return this;
        }
        @CustomType.Setter
        public Builder iclExamples(@Nullable AgentToolToolConfigIclExamples iclExamples) {

            this.iclExamples = iclExamples;
            return this;
        }
        @CustomType.Setter
        public Builder knowledgeBaseConfigs(@Nullable List<AgentToolToolConfigKnowledgeBaseConfig> knowledgeBaseConfigs) {

            this.knowledgeBaseConfigs = knowledgeBaseConfigs;
            return this;
        }
        public Builder knowledgeBaseConfigs(AgentToolToolConfigKnowledgeBaseConfig... knowledgeBaseConfigs) {
            return knowledgeBaseConfigs(List.of(knowledgeBaseConfigs));
        }
        @CustomType.Setter
        public Builder modelSize(@Nullable String modelSize) {

            this.modelSize = modelSize;
            return this;
        }
        @CustomType.Setter
        public Builder shouldEnableSelfCorrection(@Nullable Boolean shouldEnableSelfCorrection) {

            this.shouldEnableSelfCorrection = shouldEnableSelfCorrection;
            return this;
        }
        @CustomType.Setter
        public Builder shouldEnableSqlExecution(@Nullable Boolean shouldEnableSqlExecution) {

            this.shouldEnableSqlExecution = shouldEnableSqlExecution;
            return this;
        }
        @CustomType.Setter
        public Builder tableAndColumnDescription(@Nullable AgentToolToolConfigTableAndColumnDescription tableAndColumnDescription) {

            this.tableAndColumnDescription = tableAndColumnDescription;
            return this;
        }
        @CustomType.Setter
        public Builder toolConfigType(String toolConfigType) {
            if (toolConfigType == null) {
              throw new MissingRequiredPropertyException("AgentToolToolConfig", "toolConfigType");
            }
            this.toolConfigType = toolConfigType;
            return this;
        }
        public AgentToolToolConfig build() {
            final var _resultValue = new AgentToolToolConfig();
            _resultValue.databaseConnection = databaseConnection;
            _resultValue.databaseSchema = databaseSchema;
            _resultValue.dialect = dialect;
            _resultValue.function = function;
            _resultValue.generationLlmCustomization = generationLlmCustomization;
            _resultValue.iclExamples = iclExamples;
            _resultValue.knowledgeBaseConfigs = knowledgeBaseConfigs;
            _resultValue.modelSize = modelSize;
            _resultValue.shouldEnableSelfCorrection = shouldEnableSelfCorrection;
            _resultValue.shouldEnableSqlExecution = shouldEnableSqlExecution;
            _resultValue.tableAndColumnDescription = tableAndColumnDescription;
            _resultValue.toolConfigType = toolConfigType;
            return _resultValue;
        }
    }
}
