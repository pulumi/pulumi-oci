// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.GetFleetTargetsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetFleetTargetsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetFleetTargetsArgs Empty = new GetFleetTargetsArgs();

    /**
     * A filter to return only resources that match the entire display name given.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetFleetTargetsFilterArgs>> filters;

    public Optional<Output<List<GetFleetTargetsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Unique Fleet identifier.
     * 
     */
    @Import(name="fleetId", required=true)
    private Output<String> fleetId;

    /**
     * @return Unique Fleet identifier.
     * 
     */
    public Output<String> fleetId() {
        return this.fleetId;
    }

    /**
     * Product Name.
     * 
     */
    @Import(name="product")
    private @Nullable Output<String> product;

    /**
     * @return Product Name.
     * 
     */
    public Optional<Output<String>> product() {
        return Optional.ofNullable(this.product);
    }

    /**
     * Resource Display Name.
     * 
     */
    @Import(name="resourceDisplayName")
    private @Nullable Output<String> resourceDisplayName;

    /**
     * @return Resource Display Name.
     * 
     */
    public Optional<Output<String>> resourceDisplayName() {
        return Optional.ofNullable(this.resourceDisplayName);
    }

    /**
     * Resource Identifier
     * 
     */
    @Import(name="resourceId")
    private @Nullable Output<String> resourceId;

    /**
     * @return Resource Identifier
     * 
     */
    public Optional<Output<String>> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }

    private GetFleetTargetsArgs() {}

    private GetFleetTargetsArgs(GetFleetTargetsArgs $) {
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.fleetId = $.fleetId;
        this.product = $.product;
        this.resourceDisplayName = $.resourceDisplayName;
        this.resourceId = $.resourceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetFleetTargetsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetFleetTargetsArgs $;

        public Builder() {
            $ = new GetFleetTargetsArgs();
        }

        public Builder(GetFleetTargetsArgs defaults) {
            $ = new GetFleetTargetsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the entire display name given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetFleetTargetsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetFleetTargetsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetFleetTargetsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param fleetId Unique Fleet identifier.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(Output<String> fleetId) {
            $.fleetId = fleetId;
            return this;
        }

        /**
         * @param fleetId Unique Fleet identifier.
         * 
         * @return builder
         * 
         */
        public Builder fleetId(String fleetId) {
            return fleetId(Output.of(fleetId));
        }

        /**
         * @param product Product Name.
         * 
         * @return builder
         * 
         */
        public Builder product(@Nullable Output<String> product) {
            $.product = product;
            return this;
        }

        /**
         * @param product Product Name.
         * 
         * @return builder
         * 
         */
        public Builder product(String product) {
            return product(Output.of(product));
        }

        /**
         * @param resourceDisplayName Resource Display Name.
         * 
         * @return builder
         * 
         */
        public Builder resourceDisplayName(@Nullable Output<String> resourceDisplayName) {
            $.resourceDisplayName = resourceDisplayName;
            return this;
        }

        /**
         * @param resourceDisplayName Resource Display Name.
         * 
         * @return builder
         * 
         */
        public Builder resourceDisplayName(String resourceDisplayName) {
            return resourceDisplayName(Output.of(resourceDisplayName));
        }

        /**
         * @param resourceId Resource Identifier
         * 
         * @return builder
         * 
         */
        public Builder resourceId(@Nullable Output<String> resourceId) {
            $.resourceId = resourceId;
            return this;
        }

        /**
         * @param resourceId Resource Identifier
         * 
         * @return builder
         * 
         */
        public Builder resourceId(String resourceId) {
            return resourceId(Output.of(resourceId));
        }

        public GetFleetTargetsArgs build() {
            if ($.fleetId == null) {
                throw new MissingRequiredPropertyException("GetFleetTargetsArgs", "fleetId");
            }
            return $;
        }
    }

}
