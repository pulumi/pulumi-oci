// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Desktops.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Desktops.inputs.GetDesktopPoolDesktopsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDesktopPoolDesktopsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDesktopPoolDesktopsPlainArgs Empty = new GetDesktopPoolDesktopsPlainArgs();

    /**
     * The name of the availability domain.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable String availabilityDomain;

    /**
     * @return The name of the availability domain.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The OCID of the compartment of the desktop pool.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The OCID of the compartment of the desktop pool.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    /**
     * The OCID of the desktop pool.
     * 
     */
    @Import(name="desktopPoolId", required=true)
    private String desktopPoolId;

    /**
     * @return The OCID of the desktop pool.
     * 
     */
    public String desktopPoolId() {
        return this.desktopPoolId;
    }

    /**
     * A filter to return only results with the given displayName.
     * 
     */
    @Import(name="displayName")
    private @Nullable String displayName;

    /**
     * @return A filter to return only results with the given displayName.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable List<GetDesktopPoolDesktopsFilter> filters;

    public Optional<List<GetDesktopPoolDesktopsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only results with the given OCID.
     * 
     */
    @Import(name="id")
    private @Nullable String id;

    /**
     * @return A filter to return only results with the given OCID.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * A filter to return only results with the given lifecycleState.
     * 
     */
    @Import(name="state")
    private @Nullable String state;

    /**
     * @return A filter to return only results with the given lifecycleState.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    private GetDesktopPoolDesktopsPlainArgs() {}

    private GetDesktopPoolDesktopsPlainArgs(GetDesktopPoolDesktopsPlainArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.desktopPoolId = $.desktopPoolId;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.id = $.id;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDesktopPoolDesktopsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDesktopPoolDesktopsPlainArgs $;

        public Builder() {
            $ = new GetDesktopPoolDesktopsPlainArgs();
        }

        public Builder(GetDesktopPoolDesktopsPlainArgs defaults) {
            $ = new GetDesktopPoolDesktopsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain The name of the availability domain.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment of the desktop pool.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param desktopPoolId The OCID of the desktop pool.
         * 
         * @return builder
         * 
         */
        public Builder desktopPoolId(String desktopPoolId) {
            $.desktopPoolId = desktopPoolId;
            return this;
        }

        /**
         * @param displayName A filter to return only results with the given displayName.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable String displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder filters(@Nullable List<GetDesktopPoolDesktopsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetDesktopPoolDesktopsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param id A filter to return only results with the given OCID.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable String id) {
            $.id = id;
            return this;
        }

        /**
         * @param state A filter to return only results with the given lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable String state) {
            $.state = state;
            return this;
        }

        public GetDesktopPoolDesktopsPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDesktopPoolDesktopsPlainArgs", "compartmentId");
            }
            if ($.desktopPoolId == null) {
                throw new MissingRequiredPropertyException("GetDesktopPoolDesktopsPlainArgs", "desktopPoolId");
            }
            return $;
        }
    }

}
