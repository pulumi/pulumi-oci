// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetVolumesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVolumesPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVolumesPlainArgs Empty = new GetVolumesPlainArgs();

    /**
     * The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * A filter to return only resources that match the given cluster placement group Id exactly.
     * 
     */
    @Import(name="clusterPlacementGroupId")
    private @Nullable String clusterPlacementGroupId;

    /**
     * @return A filter to return only resources that match the given cluster placement group Id exactly.
     * 
     */
    public Optional<String> clusterPlacementGroupId() {
        return Optional.ofNullable(this.clusterPlacementGroupId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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
    private @Nullable List<GetVolumesFilter> filters;

    public Optional<List<GetVolumesFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The OCID of the volume group.
     * 
     */
    @Import(name="volumeGroupId")
    private @Nullable String volumeGroupId;

    /**
     * @return The OCID of the volume group.
     * 
     */
    public Optional<String> volumeGroupId() {
        return Optional.ofNullable(this.volumeGroupId);
    }

    private GetVolumesPlainArgs() {}

    private GetVolumesPlainArgs(GetVolumesPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.clusterPlacementGroupId = $.clusterPlacementGroupId;
        this.compartmentId = $.compartmentId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.state = $.state;
        this.volumeGroupId = $.volumeGroupId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVolumesPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVolumesPlainArgs $;

        public Builder() {
            $ = new GetVolumesPlainArgs();
        }

        public Builder(GetVolumesPlainArgs defaults) {
            $ = new GetVolumesPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.  Example: `Uocm:PHX-AD-1`
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param clusterPlacementGroupId A filter to return only resources that match the given cluster placement group Id exactly.
         * 
         * @return builder
         * 
         */
        public Builder clusterPlacementGroupId(@Nullable String clusterPlacementGroupId) {
            $.clusterPlacementGroupId = clusterPlacementGroupId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
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

        public Builder filters(@Nullable List<GetVolumesFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetVolumesFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param state A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        /**
         * @param volumeGroupId The OCID of the volume group.
         * 
         * @return builder
         * 
         */
        public Builder volumeGroupId(@Nullable String volumeGroupId) {
            $.volumeGroupId = volumeGroupId;
            return this;
        }

        public GetVolumesPlainArgs build() {
            return $;
        }
    }

}
