// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.inputs.GetUsersFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetUsersArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUsersArgs Empty = new GetUsersArgs();

    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the compartment (remember that the tenancy is simply the root compartment).
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The id of a user in the identity provider.
     * 
     */
    @Import(name="externalIdentifier")
    private @Nullable Output<String> externalIdentifier;

    /**
     * @return The id of a user in the identity provider.
     * 
     */
    public Optional<Output<String>> externalIdentifier() {
        return Optional.ofNullable(this.externalIdentifier);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetUsersFilterArgs>> filters;

    public Optional<Output<List<GetUsersFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * The id of the identity provider.
     * 
     */
    @Import(name="identityProviderId")
    private @Nullable Output<String> identityProviderId;

    /**
     * @return The id of the identity provider.
     * 
     */
    public Optional<Output<String>> identityProviderId() {
        return Optional.ofNullable(this.identityProviderId);
    }

    /**
     * A filter to only return resources that match the given name exactly.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to only return resources that match the given name exactly.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetUsersArgs() {}

    private GetUsersArgs(GetUsersArgs $) {
        this.compartmentId = $.compartmentId;
        this.externalIdentifier = $.externalIdentifier;
        this.filters = $.filters;
        this.identityProviderId = $.identityProviderId;
        this.name = $.name;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUsersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUsersArgs $;

        public Builder() {
            $ = new GetUsersArgs();
        }

        public Builder(GetUsersArgs defaults) {
            $ = new GetUsersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment (remember that the tenancy is simply the root compartment).
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param externalIdentifier The id of a user in the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder externalIdentifier(@Nullable Output<String> externalIdentifier) {
            $.externalIdentifier = externalIdentifier;
            return this;
        }

        /**
         * @param externalIdentifier The id of a user in the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder externalIdentifier(String externalIdentifier) {
            return externalIdentifier(Output.of(externalIdentifier));
        }

        public Builder filters(@Nullable Output<List<GetUsersFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetUsersFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetUsersFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param identityProviderId The id of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(@Nullable Output<String> identityProviderId) {
            $.identityProviderId = identityProviderId;
            return this;
        }

        /**
         * @param identityProviderId The id of the identity provider.
         * 
         * @return builder
         * 
         */
        public Builder identityProviderId(String identityProviderId) {
            return identityProviderId(Output.of(identityProviderId));
        }

        /**
         * @param name A filter to only return resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to only return resources that match the given name exactly.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetUsersArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetUsersArgs", "compartmentId");
            }
            return $;
        }
    }

}
