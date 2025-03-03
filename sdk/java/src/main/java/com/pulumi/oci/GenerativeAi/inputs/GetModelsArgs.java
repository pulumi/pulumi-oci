// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GenerativeAi.inputs.GetModelsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetModelsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetModelsArgs Empty = new GetModelsArgs();

    /**
     * A filter to return only resources their capability matches the given capability.
     * 
     */
    @Import(name="capabilities")
    private @Nullable Output<List<String>> capabilities;

    /**
     * @return A filter to return only resources their capability matches the given capability.
     * 
     */
    public Optional<Output<List<String>>> capabilities() {
        return Optional.ofNullable(this.capabilities);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
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
     * The ID of the model.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The ID of the model.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * A filter to return only resources that match the entire vendor given.
     * 
     */
    @Import(name="vendor")
    private @Nullable Output<String> vendor;

    /**
     * @return A filter to return only resources that match the entire vendor given.
     * 
     */
    public Optional<Output<String>> vendor() {
        return Optional.ofNullable(this.vendor);
    }

    private GetModelsArgs() {}

    private GetModelsArgs(GetModelsArgs $) {
        this.capabilities = $.capabilities;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.state = $.state;
        this.vendor = $.vendor;
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
         * @param capabilities A filter to return only resources their capability matches the given capability.
         * 
         * @return builder
         * 
         */
        public Builder capabilities(@Nullable Output<List<String>> capabilities) {
            $.capabilities = capabilities;
            return this;
        }

        /**
         * @param capabilities A filter to return only resources their capability matches the given capability.
         * 
         * @return builder
         * 
         */
        public Builder capabilities(List<String> capabilities) {
            return capabilities(Output.of(capabilities));
        }

        /**
         * @param capabilities A filter to return only resources their capability matches the given capability.
         * 
         * @return builder
         * 
         */
        public Builder capabilities(String... capabilities) {
            return capabilities(List.of(capabilities));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
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
         * @param id The ID of the model.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The ID of the model.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param vendor A filter to return only resources that match the entire vendor given.
         * 
         * @return builder
         * 
         */
        public Builder vendor(@Nullable Output<String> vendor) {
            $.vendor = vendor;
            return this;
        }

        /**
         * @param vendor A filter to return only resources that match the entire vendor given.
         * 
         * @return builder
         * 
         */
        public Builder vendor(String vendor) {
            return vendor(Output.of(vendor));
        }

        public GetModelsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetModelsArgs", "compartmentId");
            }
            return $;
        }
    }

}
