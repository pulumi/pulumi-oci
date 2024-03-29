// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Bastion.inputs.GetBastionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetBastionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBastionsArgs Empty = new GetBastionsArgs();

    /**
     * The unique identifier (OCID) of the bastion in which to list resources.
     * 
     */
    @Import(name="bastionId")
    private @Nullable Output<String> bastionId;

    /**
     * @return The unique identifier (OCID) of the bastion in which to list resources.
     * 
     */
    public Optional<Output<String>> bastionId() {
        return Optional.ofNullable(this.bastionId);
    }

    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    @Import(name="bastionLifecycleState")
    private @Nullable Output<String> bastionLifecycleState;

    /**
     * @return A filter to return only resources their lifecycleState matches the given lifecycleState.
     * 
     */
    public Optional<Output<String>> bastionLifecycleState() {
        return Optional.ofNullable(this.bastionLifecycleState);
    }

    /**
     * The unique identifier (OCID) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The unique identifier (OCID) of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable Output<List<GetBastionsFilterArgs>> filters;

    public Optional<Output<List<GetBastionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only resources that match the entire name given.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return only resources that match the entire name given.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    private GetBastionsArgs() {}

    private GetBastionsArgs(GetBastionsArgs $) {
        this.bastionId = $.bastionId;
        this.bastionLifecycleState = $.bastionLifecycleState;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBastionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBastionsArgs $;

        public Builder() {
            $ = new GetBastionsArgs();
        }

        public Builder(GetBastionsArgs defaults) {
            $ = new GetBastionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param bastionId The unique identifier (OCID) of the bastion in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder bastionId(@Nullable Output<String> bastionId) {
            $.bastionId = bastionId;
            return this;
        }

        /**
         * @param bastionId The unique identifier (OCID) of the bastion in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder bastionId(String bastionId) {
            return bastionId(Output.of(bastionId));
        }

        /**
         * @param bastionLifecycleState A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder bastionLifecycleState(@Nullable Output<String> bastionLifecycleState) {
            $.bastionLifecycleState = bastionLifecycleState;
            return this;
        }

        /**
         * @param bastionLifecycleState A filter to return only resources their lifecycleState matches the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder bastionLifecycleState(String bastionLifecycleState) {
            return bastionLifecycleState(Output.of(bastionLifecycleState));
        }

        /**
         * @param compartmentId The unique identifier (OCID) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The unique identifier (OCID) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetBastionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetBastionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetBastionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param name A filter to return only resources that match the entire name given.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return only resources that match the entire name given.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        public GetBastionsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetBastionsArgs", "compartmentId");
            }
            return $;
        }
    }

}
