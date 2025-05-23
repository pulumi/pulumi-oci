// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.inputs.GetModelsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetModelsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelsArgs Empty = new GetModelsArgs();

    /**
     * Specifies the type of models to list. By default, user models are listed.
     * 
     */
    @Import(name="category")
    private @Nullable Output<String> category;

    /**
     * @return Specifies the type of models to list. By default, user models are listed.
     * 
     */
    public Optional<Output<String>> category() {
        return Optional.ofNullable(this.category);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    @Import(name="createdBy")
    private @Nullable Output<String> createdBy;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     * 
     */
    public Optional<Output<String>> createdBy() {
        return Optional.ofNullable(this.createdBy);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetModelsFilterArgs>> filters;

    public Optional<Output<List<GetModelsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The OCID of the model version set that the model is associated to.
     * 
     */
    @Import(name="modelVersionSetId")
    private @Nullable Output<String> modelVersionSetId;

    /**
     * @return The OCID of the model version set that the model is associated to.
     * 
     */
    public Optional<Output<String>> modelVersionSetId() {
        return Optional.ofNullable(this.modelVersionSetId);
    }

    /**
     * The name of the model version set that the model is associated to.
     * 
     */
    @Import(name="modelVersionSetName")
    private @Nullable Output<String> modelVersionSetName;

    /**
     * @return The name of the model version set that the model is associated to.
     * 
     */
    public Optional<Output<String>> modelVersionSetName() {
        return Optional.ofNullable(this.modelVersionSetName);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     * 
     */
    @Import(name="projectId")
    private @Nullable Output<String> projectId;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
     * 
     */
    public Optional<Output<String>> projectId() {
        return Optional.ofNullable(this.projectId);
    }

    /**
     * &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="versionLabel")
    private @Nullable Output<String> versionLabel;

    public Optional<Output<String>> versionLabel() {
        return Optional.ofNullable(this.versionLabel);
    }

    private GetModelsArgs() {}

    private GetModelsArgs(GetModelsArgs $) {
        this.category = $.category;
        this.compartmentId = $.compartmentId;
        this.createdBy = $.createdBy;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.modelVersionSetId = $.modelVersionSetId;
        this.modelVersionSetName = $.modelVersionSetName;
        this.projectId = $.projectId;
        this.state = $.state;
        this.versionLabel = $.versionLabel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetModelsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetModelsArgs $;

        public Builder() {
            $ = new GetModelsArgs();
        }

        public Builder(GetModelsArgs defaults) {
            $ = new GetModelsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param category Specifies the type of models to list. By default, user models are listed.
         * 
         * @return builder
         * 
         */
        public Builder category(@Nullable Output<String> category) {
            $.category = category;
            return this;
        }

        /**
         * @param category Specifies the type of models to list. By default, user models are listed.
         * 
         * @return builder
         * 
         */
        public Builder category(String category) {
            return category(Output.of(category));
        }

        /**
         * @param compartmentId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param createdBy &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(@Nullable Output<String> createdBy) {
            $.createdBy = createdBy;
            return this;
        }

        /**
         * @param createdBy &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
         * 
         * @return builder
         * 
         */
        public Builder createdBy(String createdBy) {
            return createdBy(Output.of(createdBy));
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName &lt;b&gt;Filter&lt;/b&gt; results by its user-friendly name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetModelsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetModelsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetModelsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id &lt;b&gt;Filter&lt;/b&gt; results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param modelVersionSetId The OCID of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(@Nullable Output<String> modelVersionSetId) {
            $.modelVersionSetId = modelVersionSetId;
            return this;
        }

        /**
         * @param modelVersionSetId The OCID of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetId(String modelVersionSetId) {
            return modelVersionSetId(Output.of(modelVersionSetId));
        }

        /**
         * @param modelVersionSetName The name of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetName(@Nullable Output<String> modelVersionSetName) {
            $.modelVersionSetName = modelVersionSetName;
            return this;
        }

        /**
         * @param modelVersionSetName The name of the model version set that the model is associated to.
         * 
         * @return builder
         * 
         */
        public Builder modelVersionSetName(String modelVersionSetName) {
            return modelVersionSetName(Output.of(modelVersionSetName));
        }

        /**
         * @param projectId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
         * 
         * @return builder
         * 
         */
        public Builder projectId(@Nullable Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param state &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state &lt;b&gt;Filter&lt;/b&gt; results by the specified lifecycle state. Must be a valid state for the resource type.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder versionLabel(@Nullable Output<String> versionLabel) {
            $.versionLabel = versionLabel;
            return this;
        }

        public Builder versionLabel(String versionLabel) {
            return versionLabel(Output.of(versionLabel));
        }

        public GetModelsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetModelsArgs", "compartmentId");
            }
            return $;
        }
    }

}
