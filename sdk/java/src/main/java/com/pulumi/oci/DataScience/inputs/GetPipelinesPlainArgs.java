// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.GetPipelinesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetPipelinesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetPipelinesPlainArgs Empty = new GetPipelinesPlainArgs();

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
    private @Nullable List<GetPipelinesFilter> filters;

    public Optional<List<GetPipelinesFilter>> filters() {
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
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     * 
     */
    @Import(name="projectId")
    private @Nullable String projectId;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     * 
     */
    public Optional<String> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * The current state of the Pipeline.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return The current state of the Pipeline.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetPipelinesPlainArgs() {}

    private GetPipelinesPlainArgs(GetPipelinesPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.projectId = $.projectId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetPipelinesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetPipelinesPlainArgs $;

        public Builder() {
            $ = new GetPipelinesPlainArgs();
        }

        public Builder(GetPipelinesPlainArgs defaults) {
            $ = new GetPipelinesPlainArgs(Objects.requireNonNull(defaults));
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

        public Builder filters(@Nullable List<GetPipelinesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetPipelinesFilter... filters) {
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
         * @param projectId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable String projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param state The current state of the Pipeline.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetPipelinesPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetPipelinesPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
