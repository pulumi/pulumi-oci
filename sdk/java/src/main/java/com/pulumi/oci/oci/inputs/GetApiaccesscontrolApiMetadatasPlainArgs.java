// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.oci.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.oci.inputs.GetApiaccesscontrolApiMetadatasFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetApiaccesscontrolApiMetadatasPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetApiaccesscontrolApiMetadatasPlainArgs Empty = new GetApiaccesscontrolApiMetadatasPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * A filter to return only resources that match the given display name exactly.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only resources that match the given display name exactly.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetApiaccesscontrolApiMetadatasFilter> filters;

    public Optional<List<GetApiaccesscontrolApiMetadatasFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only lists of resources that match the entire given service type.
     * 
     */
    @Import(name="resourceType")
    private @Nullable String resourceType;

    /**
     * @return A filter to return only lists of resources that match the entire given service type.
     * 
     */
    public Optional<String> resourceType() {
        return Optional.ofNullable(this.resourceType);
    }

    /**
     * A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetApiaccesscontrolApiMetadatasPlainArgs() {}

    private GetApiaccesscontrolApiMetadatasPlainArgs(GetApiaccesscontrolApiMetadatasPlainArgs $) {
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.resourceType = $.resourceType;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetApiaccesscontrolApiMetadatasPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetApiaccesscontrolApiMetadatasPlainArgs $;

        public Builder() {
            $ = new GetApiaccesscontrolApiMetadatasPlainArgs();
        }

        public Builder(GetApiaccesscontrolApiMetadatasPlainArgs defaults) {
            $ = new GetApiaccesscontrolApiMetadatasPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the given display name exactly.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetApiaccesscontrolApiMetadatasFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetApiaccesscontrolApiMetadatasFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param resourceType A filter to return only lists of resources that match the entire given service type.
         * 
         * @return builder
         * 
         */
        public Builder resourceType(@Nullable String resourceType) {
            $.resourceType = resourceType;
            return this;
        }

        /**
         * @param state A filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetApiaccesscontrolApiMetadatasPlainArgs build() {
            return $;
        }
    }

}
