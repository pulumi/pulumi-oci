// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataScience.inputs.GetPipelineRunsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPipelineRunsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPipelineRunsPlainArgs Empty = new GetPipelineRunsPlainArgs();

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    @Import(name="createdBy")
    private @Nullable String createdBy;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    public Optional<String> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetPipelineRunsFilter> filters;

    public Optional<List<GetPipelineRunsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
     * 
     */
    @Import(name="pipelineId")
    private @Nullable String pipelineId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
     * 
     */
    public Optional<String> pipelineId() {
        return Optional.ofNullable(this.pipelineId);
    }

    /**
     * The current state of the PipelineRun.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the PipelineRun.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetPipelineRunsPlainArgs() {}

    private GetPipelineRunsPlainArgs(GetPipelineRunsPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.pipelineId = $.pipelineId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPipelineRunsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPipelineRunsPlainArgs $;

        public Builder() {
            $ = new GetPipelineRunsPlainArgs();
        }

        public Builder(GetPipelineRunsPlainArgs defaults) {
            $ = new GetPipelineRunsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param createdBy &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable String createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetPipelineRunsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPipelineRunsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param pipelineId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pipeline.
         * 
         * @return builder
         * 
         */
        public Builder pipelineId(@Nullable String pipelineId) {
            $.pipelineId = pipelineId;
            return this;
        }

        /**
         * @param state The current state of the PipelineRun.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetPipelineRunsPlainArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}