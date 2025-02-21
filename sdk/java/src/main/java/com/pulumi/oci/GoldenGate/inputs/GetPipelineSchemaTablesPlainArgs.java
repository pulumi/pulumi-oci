// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.inputs.GetPipelineSchemaTablesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPipelineSchemaTablesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPipelineSchemaTablesPlainArgs Empty = new GetPipelineSchemaTablesPlainArgs();

    /**
     * A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetPipelineSchemaTablesFilter> filters;

    public Optional<List<GetPipelineSchemaTablesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline created.
     * 
     */
    @Import(name="pipelineId", required=true)
    private String pipelineId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline created.
     * 
     */
    public String pipelineId() {
        return this.pipelineId;
    }

    /**
     * Name of the source schema obtained from get schema endpoint of the created pipeline.
     * 
     */
    @Import(name="sourceSchemaName", required=true)
    private String sourceSchemaName;

    /**
     * @return Name of the source schema obtained from get schema endpoint of the created pipeline.
     * 
     */
    public String sourceSchemaName() {
        return this.sourceSchemaName;
    }

    /**
     * Name of the target schema obtained from get schema endpoint of the created pipeline.
     * 
     */
    @Import(name="targetSchemaName", required=true)
    private String targetSchemaName;

    /**
     * @return Name of the target schema obtained from get schema endpoint of the created pipeline.
     * 
     */
    public String targetSchemaName() {
        return this.targetSchemaName;
    }

    private GetPipelineSchemaTablesPlainArgs() {}

    private GetPipelineSchemaTablesPlainArgs(GetPipelineSchemaTablesPlainArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.pipelineId = $.pipelineId;
        this.sourceSchemaName = $.sourceSchemaName;
        this.targetSchemaName = $.targetSchemaName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPipelineSchemaTablesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPipelineSchemaTablesPlainArgs $;

        public Builder() {
            $ = new GetPipelineSchemaTablesPlainArgs();
        }

        public Builder(GetPipelineSchemaTablesPlainArgs defaults) {
            $ = new GetPipelineSchemaTablesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire &#39;displayName&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetPipelineSchemaTablesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPipelineSchemaTablesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param pipelineId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline created.
         * 
         * @return builder
         * 
         */
        public Builder pipelineId(String pipelineId) {
            $.pipelineId = pipelineId;
            return this;
        }

        /**
         * @param sourceSchemaName Name of the source schema obtained from get schema endpoint of the created pipeline.
         * 
         * @return builder
         * 
         */
        public Builder sourceSchemaName(String sourceSchemaName) {
            $.sourceSchemaName = sourceSchemaName;
            return this;
        }

        /**
         * @param targetSchemaName Name of the target schema obtained from get schema endpoint of the created pipeline.
         * 
         * @return builder
         * 
         */
        public Builder targetSchemaName(String targetSchemaName) {
            $.targetSchemaName = targetSchemaName;
            return this;
        }

        public GetPipelineSchemaTablesPlainArgs build() {
            if ($.pipelineId == null) {
                throw new MissingRequiredPropertyException("GetPipelineSchemaTablesPlainArgs", "pipelineId");
            }
            if ($.sourceSchemaName == null) {
                throw new MissingRequiredPropertyException("GetPipelineSchemaTablesPlainArgs", "sourceSchemaName");
            }
            if ($.targetSchemaName == null) {
                throw new MissingRequiredPropertyException("GetPipelineSchemaTablesPlainArgs", "targetSchemaName");
            }
            return $;
        }
    }

}
